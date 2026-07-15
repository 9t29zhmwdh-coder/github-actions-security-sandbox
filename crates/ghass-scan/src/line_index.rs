//! Best-effort YAML line lookup for jobs and steps.
//!
//! `serde_yaml::Value` carries no span/location information, and swapping the
//! YAML library for a span-aware one (e.g. `saphyr`) is a bigger, riskier
//! change than this tool needs for "point me at roughly the right line" SARIF
//! output. Instead this does a second, independent text pass over the raw
//! workflow source using simple indentation-based anchors. It is deliberately
//! a heuristic, not a real YAML parser: it can be fooled by unusual
//! formatting (tabs, flow-style `steps: [...]`, anchors/aliases), but for the
//! overwhelming majority of real-world GitHub Actions workflows -- block
//! style, space-indented -- it finds the right line.

use std::collections::HashMap;

pub struct LineIndex {
    job_lines: HashMap<String, usize>,
    step_lines: HashMap<String, Vec<usize>>,
}

impl LineIndex {
    pub fn build(content: &str) -> LineIndex {
        let lines: Vec<&str> = content.lines().collect();
        let mut job_lines = HashMap::new();
        let mut step_lines: HashMap<String, Vec<usize>> = HashMap::new();

        let Some(jobs_key_line) = find_top_level_key_line(&lines, "jobs") else {
            return LineIndex { job_lines, step_lines };
        };

        let Some(job_indent) = first_non_blank_indent_after(&lines, jobs_key_line) else {
            return LineIndex { job_lines, step_lines };
        };

        for (id, start, end) in find_mapping_entries(&lines, jobs_key_line + 1, job_indent) {
            job_lines.insert(id.clone(), start + 1);
            if let Some(steps) = find_step_lines(&lines, start, end) {
                step_lines.insert(id, steps.iter().map(|l| l + 1).collect());
            }
        }

        LineIndex { job_lines, step_lines }
    }

    pub fn job_line(&self, job_id: &str) -> Option<usize> {
        self.job_lines.get(job_id).copied()
    }

    pub fn step_line(&self, job_id: &str, step_index: usize) -> Option<usize> {
        self.step_lines.get(job_id)?.get(step_index).copied()
    }
}

fn leading_spaces(line: &str) -> usize {
    line.chars().take_while(|c| *c == ' ').count()
}

/// If `line` looks like a YAML mapping key (`key:` or `key: value`, not a
/// sequence item and not a comment), return the key with surrounding quotes
/// stripped.
fn mapping_key(line: &str) -> Option<String> {
    let trimmed = line.trim_start();
    if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with('-') {
        return None;
    }
    let idx = trimmed.find(':')?;
    let key = trimmed[..idx].trim();
    if key.is_empty() {
        return None;
    }
    Some(key.trim_matches('"').trim_matches('\'').to_string())
}

fn find_top_level_key_line(lines: &[&str], key: &str) -> Option<usize> {
    lines
        .iter()
        .enumerate()
        .find(|(_, l)| leading_spaces(l) == 0 && mapping_key(l).as_deref() == Some(key))
        .map(|(i, _)| i)
}

fn first_non_blank_indent_after(lines: &[&str], after: usize) -> Option<usize> {
    lines[after + 1..]
        .iter()
        .find(|l| !l.trim().is_empty())
        .map(|l| leading_spaces(l))
}

/// Find each `key:` mapping entry at exactly `indent` starting at `from`,
/// stopping once a non-blank line dedents below `indent`. Returns
/// `(key, start_line, end_line_exclusive)` triples, `end` being either the
/// next sibling entry's start or the dedent point.
fn find_mapping_entries(
    lines: &[&str],
    from: usize,
    indent: usize,
) -> Vec<(String, usize, usize)> {
    let mut entries = vec![];
    let mut i = from;
    while i < lines.len() {
        let line = lines[i];
        if line.trim().is_empty() {
            i += 1;
            continue;
        }
        let this_indent = leading_spaces(line);
        if this_indent < indent {
            break;
        }
        if this_indent == indent {
            if let Some(key) = mapping_key(line) {
                let start = i;
                let mut end = lines.len();
                for (j, l2) in lines.iter().enumerate().skip(i + 1) {
                    if l2.trim().is_empty() {
                        continue;
                    }
                    if leading_spaces(l2) <= indent {
                        end = j;
                        break;
                    }
                }
                entries.push((key, start, end));
                i = end;
                continue;
            }
        }
        i += 1;
    }
    entries
}

/// Within `[start, end)`, find a `steps:` key and index each `- ` sequence
/// item directly under it as one step, in document order.
fn find_step_lines(lines: &[&str], start: usize, end: usize) -> Option<Vec<usize>> {
    let steps_key_line = (start..end).find(|&i| mapping_key(lines[i]).as_deref() == Some("steps"))?;
    let item_indent = first_non_blank_indent_after(lines, steps_key_line)?;
    if !lines
        .get(steps_key_line + 1..end)
        .and_then(|s| s.iter().find(|l| !l.trim().is_empty()))
        .map(|l| l.trim_start().starts_with('-'))
        .unwrap_or(false)
    {
        return Some(vec![]);
    }

    let mut result = vec![];
    for (i, line) in lines.iter().enumerate().take(end).skip(steps_key_line + 1) {
        if line.trim().is_empty() {
            continue;
        }
        let this_indent = leading_spaces(line);
        if this_indent < item_indent {
            break;
        }
        if this_indent == item_indent && line.trim_start().starts_with('-') {
            result.push(i);
        }
    }
    Some(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
name: CI

on: push

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4
      - name: Run
        run: echo hi
  deploy:
    runs-on: ubuntu-latest
    needs: build
    steps:
      - uses: actions/checkout@v4
      - run: echo deploy
";

    #[test]
    fn finds_job_lines() {
        let idx = LineIndex::build(SAMPLE);

        assert_eq!(idx.job_line("build"), Some(6));
        assert_eq!(idx.job_line("deploy"), Some(13));
    }

    #[test]
    fn finds_step_lines_in_document_order() {
        let idx = LineIndex::build(SAMPLE);

        assert_eq!(idx.step_line("build", 0), Some(9));
        assert_eq!(idx.step_line("build", 1), Some(11));
        assert_eq!(idx.step_line("deploy", 0), Some(17));
        assert_eq!(idx.step_line("deploy", 1), Some(18));
    }

    #[test]
    fn out_of_range_step_index_returns_none() {
        let idx = LineIndex::build(SAMPLE);

        assert_eq!(idx.step_line("build", 99), None);
    }

    #[test]
    fn unknown_job_returns_none() {
        let idx = LineIndex::build(SAMPLE);

        assert_eq!(idx.job_line("nonexistent"), None);
        assert_eq!(idx.step_line("nonexistent", 0), None);
    }

    #[test]
    fn workflow_without_jobs_block_yields_empty_index() {
        let idx = LineIndex::build("name: CI\non: push\n");

        assert_eq!(idx.job_line("build"), None);
    }

    #[test]
    fn job_without_steps_key_yields_no_step_lines() {
        let idx = LineIndex::build("jobs:\n  call:\n    uses: org/repo/.github/workflows/reusable.yml@main\n");

        assert_eq!(idx.job_line("call"), Some(2));
        assert_eq!(idx.step_line("call", 0), None);
    }

    #[test]
    fn empty_steps_sequence_yields_no_step_lines() {
        let idx = LineIndex::build("jobs:\n  build:\n    runs-on: ubuntu-latest\n    steps: []\n");

        assert_eq!(idx.step_line("build", 0), None);
    }

    #[test]
    fn multiline_run_block_does_not_break_step_counting() {
        let yaml = "\
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Multi
        run: |
          echo one
          echo two
      - name: After
        run: echo three
";
        let idx = LineIndex::build(yaml);

        assert_eq!(idx.step_line("build", 0), Some(5));
        assert_eq!(idx.step_line("build", 1), Some(9));
    }

    #[test]
    fn two_space_and_four_space_indent_styles_both_work() {
        let four_space = "\
jobs:
    build:
        runs-on: ubuntu-latest
        steps:
            - name: A
              run: echo a
";
        let idx = LineIndex::build(four_space);

        assert_eq!(idx.job_line("build"), Some(2));
        assert_eq!(idx.step_line("build", 0), Some(5));
    }
}
