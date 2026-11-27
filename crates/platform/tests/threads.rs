#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, clippy::arithmetic_side_effects)]

use std::sync::atomic::{AtomicUsize, Ordering};

use debar_platform::threads::{ThreadCount, each_in_parallel};

fn threads(count: usize) -> ThreadCount {
    ThreadCount::new(count).unwrap()
}

#[test]
fn results_come_back_in_the_order_of_the_items_on_any_number_of_threads() {
    let items: Vec<u64> = (0..500).collect();
    let squares: Vec<u64> = items.iter().map(|item| item * item).collect();

    for count in [1, 2, 3, 8, 64] {
        let results = each_in_parallel(&items, threads(count), |item| item * item).unwrap();

        assert_eq!(results, squares, "{count} threads");
    }
}

#[test]
fn every_item_is_worked_on_exactly_once() {
    let items: Vec<usize> = (0..300).collect();
    let calls = AtomicUsize::new(0);

    let results = each_in_parallel(&items, threads(7), |item| {
        calls.fetch_add(1, Ordering::Relaxed);
        *item
    })
    .unwrap();

    assert_eq!(calls.load(Ordering::Relaxed), items.len());
    assert_eq!(results, items);
}

#[test]
fn more_threads_than_items_and_no_items_at_all_both_work() {
    let one = each_in_parallel(&[41], threads(16), |item| item + 1).unwrap();
    let no_items: [u8; 0] = [];
    let none = each_in_parallel(&no_items, threads(16), |item| *item).unwrap();

    assert_eq!(one, [42]);
    assert_eq!(none, []);
}

#[test]
fn a_thread_count_is_never_zero() {
    assert_eq!(ThreadCount::new(0), None);
    assert_eq!(ThreadCount::ONE.get(), 1);
}
