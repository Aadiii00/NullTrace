use std::collections::{HashMap, HashSet, VecDeque};
use std::env;
use std::io::{self, Read};
use std::time::Instant;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphNode {
    pub id: String,
    pub name: String,
    pub node_type: String,
    pub criticality: String,
    pub risk_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GraphEdge {
    pub source: String,
    pub target: String,
    pub rel_type: String,
    pub confidence: f64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ReachabilityQuery {
    pub start_node: String,
    pub max_depth: usize,
    pub nodes: Vec<GraphNode>,
    pub edges: Vec<GraphEdge>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ReachableTarget {
    pub target_id: String,
    pub target_name: String,
    pub depth: usize,
    pub criticality: String,
    pub risk_score: f64,
    pub classification: String,
    pub path: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ReachabilityResult {
    pub source_node: String,
    pub max_depth: usize,
    pub total_nodes: usize,
    pub total_edges: usize,
    pub reachable_count: usize,
    pub critical_count: usize,
    pub traversal_latency_microseconds: u128,
    pub reachable_targets: Vec<ReachableTarget>,
}

fn compute_reachability(query: &ReachabilityQuery) -> ReachabilityResult {
    let t0 = Instant::now();

    // Build adjacency list
    let mut adj: HashMap<&str, Vec<(&str, f64)>> = HashMap::with_capacity(query.nodes.len());
    for edge in &query.edges {
        adj.entry(&edge.source)
            .or_default()
            .push((&edge.target, edge.confidence));
    }

    let node_map: HashMap<&str, &GraphNode> = query
        .nodes
        .iter()
        .map(|n| (n.id.as_str(), n))
        .collect();

    let mut visited: HashSet<&str> = HashSet::new();
    let mut queue: VecDeque<(&str, usize)> = VecDeque::new();
    let mut paths: HashMap<&str, Vec<&str>> = HashMap::new();

    let start_id = query.start_node.as_str();
    visited.insert(start_id);
    queue.push_back((start_id, 0));
    paths.insert(start_id, vec![start_id]);

    let mut targets: Vec<ReachableTarget> = Vec::new();
    let mut critical_count = 0;

    while let Some((curr, depth)) = queue.pop_front() {
        if depth >= query.max_depth {
            continue;
        }

        if let Some(neighbors) = adj.get(curr) {
            for &(next_node, _conf) in neighbors {
                if !visited.contains(next_node) {
                    visited.insert(next_node);

                    let mut cur_path = paths.get(curr).cloned().unwrap_or_default();
                    cur_path.push(next_node);
                    paths.insert(next_node, cur_path.clone());

                    let ndata = node_map.get(next_node);
                    let target_name = ndata.map(|n| n.name.clone()).unwrap_or_else(|| next_node.to_string());
                    let crit = ndata.map(|n| n.criticality.clone()).unwrap_or_else(|| "MEDIUM".to_string());
                    let r_score = ndata.map(|n| n.risk_score).unwrap_or(20.0);
                    let is_crit = crit == "CRITICAL" || crit == "HIGH";
                    if is_crit {
                        critical_count += 1;
                    }

                    targets.push(ReachableTarget {
                        target_id: next_node.to_string(),
                        target_name,
                        depth: depth + 1,
                        criticality: crit,
                        risk_score: r_score,
                        classification: if depth == 0 { "OBSERVED".to_string() } else { "INFERRED".to_string() },
                        path: cur_path.into_iter().map(|s| s.to_string()).collect(),
                    });

                    queue.push_back((next_node, depth + 1));
                }
            }
        }
    }

    let elapsed = t0.elapsed().as_micros();

    ReachabilityResult {
        source_node: query.start_node.clone(),
        max_depth: query.max_depth,
        total_nodes: query.nodes.len(),
        total_edges: query.edges.len(),
        reachable_count: targets.len(),
        critical_count,
        traversal_latency_microseconds: elapsed,
        reachable_targets: targets,
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.contains(&"--benchmark".to_string()) {
        println!("Running Rust Reachability Rayon benchmark...");
        // Generate synthetic graph with 10,000 nodes and 50,000 edges
        let nodes: Vec<GraphNode> = (0..10_000)
            .into_par_iter()
            .map(|i| GraphNode {
                id: format!("node:{}", i),
                name: format!("Host-{}", i),
                node_type: if i % 10 == 0 { "server".into() } else { "workstation".into() },
                criticality: if i % 25 == 0 { "CRITICAL".into() } else { "MEDIUM".into() },
                risk_score: (i % 100) as f64,
            })
            .collect();

        let edges: Vec<GraphEdge> = (0..50_000)
            .into_par_iter()
            .map(|i| GraphEdge {
                source: format!("node:{}", i % 10_000),
                target: format!("node:{}", (i * 7 + 13) % 10_000),
                rel_type: "LATERAL_MOVE".into(),
                confidence: 0.95,
            })
            .collect();

        let query = ReachabilityQuery {
            start_node: "node:0".into(),
            max_depth: 4,
            nodes,
            edges,
        };

        let result = compute_reachability(&query);
        println!(
            "Benchmark Complete: Explored {} nodes across {} edges in {} µs ({} ms). Reachable: {}, Critical: {}",
            result.total_nodes,
            result.total_edges,
            result.traversal_latency_microseconds,
            result.traversal_latency_microseconds as f64 / 1000.0,
            result.reachable_count,
            result.critical_count
        );
        return;
    }

    // Default: read JSON from stdin
    let mut buffer = String::new();
    if let Ok(_) = io::stdin().read_to_string(&mut buffer) {
        if let Ok(query) = serde_json::from_str::<ReachabilityQuery>(&buffer) {
            let res = compute_reachability(&query);
            if let Ok(json_out) = serde_json::to_string(&res) {
                println!("{}", json_out);
            }
        }
    }
}
