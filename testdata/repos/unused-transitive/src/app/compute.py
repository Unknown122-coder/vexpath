"""Pure computation. Imports nothing from the vulnerable packages."""

from collections.abc import Sequence


def mean(values: Sequence[float]) -> float:
    if not values:
        raise ValueError("mean of an empty sequence is undefined")
    return sum(values) / len(values)


def main() -> None:
    print(mean([1.0, 2.0, 3.0]))


if __name__ == "__main__":
    main()
