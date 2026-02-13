use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::HashSet;
use std::io::{self, Read};

#[derive(Debug, Deserialize)]
struct Candidate {
    id: String,
    content: Option<String>,
    summary: Option<String>,
    importance: Option<f64>,
    recall_count: Option<i64>,
    created_at: Option<String>,
}

#[derive(Debug, Deserialize)]
struct InputPayload {
    query: String,
    limit: usize,
    min_score: f64,
    decay_days: i64,
    candidates: Vec<Candidate>,
}

#[derive(Debug, Serialize)]
struct ResultRow {
    id: String,
    score: f64,
}

#[derive(Debug, Serialize)]
struct OutputPayload {
    results: Vec<ResultRow>,
}

fn tokenize(text: &str) -> HashSet<String> {
    let stopwords: HashSet<&'static str> = HashSet::from([
        "the", "and", "for", "with", "this", "that", "from", "have", "has", "are", "was", "were", "you",
        "your", "our", "their", "then", "than", "into", "about", "what", "when", "where", "which", "will",
        "would", "could", "should", "please", "also", "just", "onto", "over", "under", "http", "https",
    ]);
    text.to_ascii_lowercase()
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '_' && c != '.' && c != '/' && c != ':' && c != '-')
        .filter(|tok| tok.len() > 2 && !stopwords.contains(*tok))
        .map(|tok| tok.to_string())
        .collect()
}

fn parse_ts(created_at: &Option<String>) -> DateTime<Utc> {
    if let Some(raw) = created_at {
        if let Ok(dt) = DateTime::parse_from_rfc3339(raw) {
            return dt.with_timezone(&Utc);
        }
        let normalized = format!("{}Z", raw);
        if let Ok(dt) = DateTime::parse_from_rfc3339(&normalized) {
            return dt.with_timezone(&Utc);
        }
    }
    Utc::now()
}

fn clamp(v: f64, min_v: f64, max_v: f64) -> f64 {
    if v < min_v {
        min_v
    } else if v > max_v {
        max_v
    } else {
        v
    }
}

fn score_candidate(query_tokens: &HashSet<String>, item: &Candidate, decay_days: i64) -> f64 {
    let text = item
        .summary
        .as_ref()
        .filter(|s| !s.is_empty())
        .or(item.content.as_ref())
        .cloned()
        .unwrap_or_default();
    let content_tokens = tokenize(&text);

    let lexical = if query_tokens.is_empty() || content_tokens.is_empty() {
        0.0
    } else {
        let overlap = query_tokens.intersection(&content_tokens).count() as f64;
        if overlap <= 0.0 {
            0.0
        } else {
            let coverage = overlap / query_tokens.len() as f64;
            let precision = overlap / content_tokens.len() as f64;
            (coverage * 0.7) + (precision * 0.3)
        }
    };

    let importance = item.importance.unwrap_or(0.0);
    let recall_count = item.recall_count.unwrap_or(0).max(0) as f64;
    let age_seconds = (Utc::now() - parse_ts(&item.created_at)).num_seconds().max(0) as f64;
    let decay_window = ((decay_days.max(1) * 24 * 3600) as f64).max(24.0 * 3600.0);
    let recency = (-age_seconds / decay_window).exp();
    let reinforcement = (1.0 + recall_count).ln() / 2.5;
    let base = (importance * 0.6) + (recency * 0.25) + (clamp(reinforcement, 0.0, 1.0) * 0.15);
    if query_tokens.is_empty() {
        clamp(base, 0.0, 1.0)
    } else {
        clamp((base * 0.5) + (lexical * 0.5), 0.0, 1.0)
    }
}

fn main() {
    let mut input = String::new();
    if io::stdin().read_to_string(&mut input).is_err() {
        let output = OutputPayload { results: Vec::new() };
        println!("{}", serde_json::to_string(&output).unwrap_or_else(|_| "{\"results\":[]}".to_string()));
        return;
    }

    let payload: InputPayload = match serde_json::from_str(&input) {
        Ok(v) => v,
        Err(_) => {
            let output = OutputPayload { results: Vec::new() };
            println!("{}", serde_json::to_string(&output).unwrap_or_else(|_| "{\"results\":[]}".to_string()));
            return;
        }
    };

    let query_tokens = tokenize(&payload.query);
    let mut scored: Vec<ResultRow> = payload
        .candidates
        .iter()
        .map(|item| ResultRow {
            id: item.id.clone(),
            score: score_candidate(&query_tokens, item, payload.decay_days),
        })
        .filter(|row| row.score >= payload.min_score)
        .collect();

    scored.sort_by(|a, b| match b.score.partial_cmp(&a.score) {
        Some(ord) => ord,
        None => Ordering::Equal,
    });

    if scored.len() > payload.limit.max(1) {
        scored.truncate(payload.limit.max(1));
    }

    let output = OutputPayload { results: scored };
    match serde_json::to_string(&output) {
        Ok(json) => println!("{json}"),
        Err(_) => println!("{{\"results\":[]}}"),
    }
}
