// SPDX-License-Identifier: GPL-3.0-only

//! Parallelism shim: rayon when `parallel` feature is on, sequential otherwise.
//! No other crate calls rayon directly.

#[cfg(feature = "parallel")]
mod imp {
    use rayon::prelude::*;

    pub fn map<T, R, F>(items: Vec<T>, f: F) -> Vec<R>
    where
        T: Send,
        R: Send,
        F: Fn(T) -> R + Sync + Send,
    {
        items.into_par_iter().map(f).collect()
    }

    pub fn for_each<T, F>(items: Vec<T>, f: F)
    where
        T: Send,
        F: Fn(T) + Sync + Send,
    {
        items.into_par_iter().for_each(f);
    }

    pub fn reduce<T, R, MapF, RedF>(items: Vec<T>, identity: R, map: MapF, reduce: RedF) -> R
    where
        T: Send,
        R: Send + Sync + Clone,
        MapF: Fn(T) -> R + Sync + Send,
        RedF: Fn(R, R) -> R + Sync + Send,
    {
        items
            .into_par_iter()
            .map(map)
            .reduce(|| identity.clone(), reduce)
    }

    pub fn sort_by_key<T, K, F>(items: &mut [T], f: F)
    where
        T: Send,
        K: Ord + Send,
        F: Fn(&T) -> K + Sync + Send,
    {
        items.par_sort_unstable_by_key(f);
    }
}

#[cfg(not(feature = "parallel"))]
mod imp {
    pub fn map<T, R, F>(items: Vec<T>, f: F) -> Vec<R>
    where
        F: Fn(T) -> R,
    {
        items.into_iter().map(f).collect()
    }

    pub fn for_each<T, F>(items: Vec<T>, f: F)
    where
        F: Fn(T),
    {
        items.into_iter().for_each(f);
    }

    pub fn reduce<T, R, MapF, RedF>(items: Vec<T>, identity: R, map: MapF, reduce: RedF) -> R
    where
        R: Clone,
        MapF: Fn(T) -> R,
        RedF: Fn(R, R) -> R,
    {
        items.into_iter().map(map).fold(identity, reduce)
    }

    pub fn sort_by_key<T, K, F>(items: &mut [T], f: F)
    where
        K: Ord,
        F: Fn(&T) -> K,
    {
        items.sort_unstable_by_key(f);
    }
}

pub use imp::{for_each, map, reduce, sort_by_key};
