// Copyright 2016 Hroi Sigurdsson
//
// Licensed under the MIT license <LICENSE-MIT or http://opensource.org/licenses/MIT>.
// This file may not be copied, modified, or distributed except according to those terms.

//! # Fast IP lookup table for IPv4/IPv6 prefixes
//!
//! This crate provides a datastructure for fast IP address lookups.
//! It aims at fast lookup times, and a small memory footprint.
//! A full IPv4 BGP table of more than 600k entries fits in less than 5 MB. A
//! full IPv6 BGP table of more than 25k entries fits in less than 1 MB.
//!
//! Longest match lookups on full BGP IP tables take on the order of 100ns.
//!
//! The internal datastructure is based on the Tree-bitmap algorithm described
//! by W. Eatherton, Z. Dittia, G. Varghes.

use std::marker::PhantomData;

mod tree_bitmap;
use tree_bitmap::TreeBitmap;

pub mod address;
use address::Address;

/// A fast, compressed IP lookup table.
pub struct IpLookupTable<A, T> {
    inner: TreeBitmap<T>,
    _addrtype: PhantomData<A>,
}

impl<A, T> IpLookupTable<A, T>
where
    A: Address,
{
    /// Initialize an empty lookup table with no preallocation.
    pub fn new() -> Self {
        IpLookupTable {
            inner: TreeBitmap::new(),
            _addrtype: PhantomData,
        }
    }

    /// Initialize an empty lookup table with pre-allocated buffers.
    pub fn with_capacity(n: usize) -> Self {
        IpLookupTable {
            inner: TreeBitmap::with_capacity(n),
            _addrtype: PhantomData,
        }
    }

    /// Return the bytes used by nodes and results.
    pub fn mem_usage(&self) -> (usize, usize) {
        self.inner.mem_usage()
    }

    /// Return number of items inside table.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// Return `true` if no item is inside table.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Insert a value for the prefix designated by ip and masklen. If prefix
    /// existed previously, the old value is returned.
    ///
    /// # Panics
    ///
    /// Panics if prefix has bits set to the right of mask.
    pub fn insert(&mut self, ip: A, masklen: u32, value: T) -> Option<T> {
        self.inner.insert(ip.nibbles().as_ref(), masklen, value)
    }

    /// Remove an entry from the lookup table. If the prefix existed previously,
    /// the value is returned.
    pub fn remove(&mut self, ip: A, masklen: u32) -> Option<T> {
        self.inner.remove(ip.nibbles().as_ref(), masklen)
    }

    /// Perform exact match lookup of `ip`/`masklen` and return the
    /// value.
    ///
    /// # Panics
    ///
    /// Panics if prefix has bits set to the right of mask.
    pub fn exact_match(&self, ip: A, masklen: u32) -> Option<&T> {
        self.inner.exact_match(ip.nibbles().as_ref(), masklen)
    }

    /// Perform exact match lookup of `ip`/`masklen` and return the
    /// value as mutable.
    pub fn exact_match_mut(&mut self, ip: A, masklen: u32) -> Option<&mut T> {
        self.inner.exact_match_mut(ip.nibbles().as_ref(), masklen)
    }

    /// Perform longest match lookup of `ip` and return the best matching
    /// prefix, designated by ip, masklen, along with its value.
    pub fn longest_match(&self, ip: A) -> Option<(A, u32, &T)> {
        match self.inner.longest_match(ip.nibbles().as_ref()) {
            Some((bits_matched, value)) => Some((ip.mask(bits_matched), bits_matched, value)),
            None => None,
        }
    }

    /// Perform longest match lookup of `ip` and return the best matching
    /// prefix, designated by ip, masklen, along with its value as mutable.
    pub fn longest_match_mut(&mut self, ip: A) -> Option<(A, u32, &mut T)> {
        match self.inner.longest_match_mut(ip.nibbles().as_ref()) {
            Some((bits_matched, value)) => Some((ip.mask(bits_matched), bits_matched, value)),
            None => None,
        }
    }

    /// Perform match lookup of `ip` and return all matching
    /// prefixes, designated by ip, masklen, along with its value.
    pub fn matches(&self, ip: A) -> impl Iterator<Item = (A, u32, &T)> {
        self.inner
            .matches(ip.nibbles().as_ref())
            .map(move |(bits_matched, value)| (ip.mask(bits_matched), bits_matched, value))
    }

    /// Perform match lookup of `ip` and return the all matching
    /// prefixes, designated by ip, masklen, along with its mutable value.
    pub fn matches_mut(&mut self, ip: A) -> impl Iterator<Item = (A, u32, &mut T)> {
        self.inner
            .matches_mut(ip.nibbles().as_ref())
            .map(move |(bits_matched, value)| (ip.mask(bits_matched), bits_matched, value))
    }

    /// Returns iterator over prefixes and values.
    pub fn iter(&self) -> Iter<'_, A, T> {
        Iter {
            inner: self.inner.iter(),
            _addrtype: PhantomData,
        }
    }

    /// Mutable version of iter().
    pub fn iter_mut(&mut self) -> IterMut<'_, A, T> {
        IterMut {
            inner: self.inner.iter_mut(),
            _addrtype: PhantomData,
        }
    }
}

impl<A, T> Default for IpLookupTable<A, T>
where
    A: Address,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<'a, A, T: 'a> Iterator for Iter<'a, A, T>
where
    A: Address,
{
    type Item = (A, u32, &'a T);

    fn next(&mut self) -> Option<Self::Item> {
        match self.inner.next() {
            Some((nibbles, masklen, value)) => {
                Some((Address::from_nibbles(&nibbles[..]), masklen, value))
            }
            None => None,
        }
    }
}

impl<'a, A, T: 'a> Iterator for IterMut<'a, A, T>
where
    A: Address,
{
    type Item = (A, u32, &'a mut T);

    fn next(&mut self) -> Option<Self::Item> {
        match self.inner.next() {
            Some((nibbles, masklen, value)) => {
                Some((Address::from_nibbles(&nibbles[..]), masklen, value))
            }
            None => None,
        }
    }
}

impl<A, T> Iterator for IntoIter<A, T>
where
    A: Address,
{
    type Item = (A, u32, T);

    fn next(&mut self) -> Option<Self::Item> {
        self.inner
            .next()
            .map(|(nibbles, masklen, value)| (Address::from_nibbles(&nibbles[..]), masklen, value))
    }
}

impl<A, T> IntoIterator for IpLookupTable<A, T>
where
    A: Address,
{
    type Item = (A, u32, T);
    type IntoIter = IntoIter<A, T>;

    fn into_iter(self) -> IntoIter<A, T> {
        IntoIter {
            inner: self.inner.into_iter(),
            _addrtype: PhantomData,
        }
    }
}

/// Iterator over prefixes and associated values. The prefixes are returned in
/// "tree"-order.
#[doc(hidden)]
pub struct Iter<'a, A, T: 'a> {
    inner: tree_bitmap::Iter<'a, T>,
    _addrtype: PhantomData<A>,
}

/// Mutable iterator over prefixes and associated values. The prefixes are
/// returned in "tree"-order.
#[doc(hidden)]
pub struct IterMut<'a, A, T: 'a> {
    inner: tree_bitmap::IterMut<'a, T>,
    _addrtype: PhantomData<A>,
}

/// Converts ```IpLookupTable``` into an iterator. The prefixes are returned in
/// "tree"-order.
#[doc(hidden)]
pub struct IntoIter<A, T> {
    inner: tree_bitmap::IntoIter<T>,
    _addrtype: PhantomData<A>,
}
