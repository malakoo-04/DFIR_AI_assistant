from __future__ import annotations

from typing import Generic, Iterable, TypeVar

T = TypeVar("T")


class UnionFind(Generic[T]):
    """
    Generic Union-Find (disjoint-set) data structure.

    Path compression is applied on lookups, and unions use a
    deterministic tie-break so that results are reproducible.

    This class is intentionally domain-agnostic: it knows nothing
    about entities, events, or any other DFIR-specific concept.
    """

    def __init__(self) -> None:
        self._parent: dict[T, T] = {}

    def make_set(self, item: T) -> None:
        """
        Register `item` as its own set, if it isn't already known.
        """

        if item not in self._parent:
            self._parent[item] = item

    def find(self, item: T) -> T:
        """
        Return the canonical representative (root) of `item`.

        Path compression is applied so that future lookups become
        nearly constant time.
        """

        root = item

        while self._parent[root] != root:
            root = self._parent[root]

        while self._parent[item] != root:
            parent = self._parent[item]
            self._parent[item] = root
            item = parent

        return root

    def union(self, item_a: T, item_b: T) -> tuple[T, T]:
        """
        Merge the sets containing `item_a` and `item_b`.

        Returns a (survivor, absorbed) tuple. The survivor is chosen
        deterministically (the smaller of the two roots) so that
        results are reproducible. If both items already belong to
        the same set, returns (root, root) and no merge occurs.
        """

        root_a = self.find(item_a)
        root_b = self.find(item_b)

        if root_a == root_b:
            return root_a, root_a

        survivor, absorbed = sorted([root_a, root_b])

        self._parent[absorbed] = survivor

        return survivor, absorbed

    def union_all(self, items: Iterable[T]) -> T:
        """
        Merge every item in `items` into a single set.

        Returns the surviving representative.
        """

        iterator = iter(items)
        survivor = next(iterator)
        self.make_set(survivor)

        for item in iterator:
            self.make_set(item)
            survivor, _ = self.union(survivor, item)

        return survivor
