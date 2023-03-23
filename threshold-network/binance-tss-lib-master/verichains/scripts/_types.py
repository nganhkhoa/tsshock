from dataclasses import dataclass
from typing import List, Tuple
from abc import ABC, abstractmethod


@dataclass
class Proof:
    alpha: List[int]
    t: List[int]


@dataclass
class Params:
    N: int
    p: int
    q: int
    h1: int
    h2: int
    proof_dlog_h2_base_h1: Proof
    proof_dlog_h1_base_h2: Proof


class Exploiter(ABC):
    @abstractmethod
    def params(self) -> Params:
        """
        Return malicious params that will be presented to other parties.
        """
        pass

    @abstractmethod
    def recover_shares(self, self_x: int, self_share: int, xz: List[Tuple[int, int]]) -> Tuple[List[int], int]:
        """
        Recover secret shares of other parties.

        `self_x` is the x-coordinate of the malicious party. `data` contains
        the parties' x-coordinate and `z` value collected at signing round 3.
        If `self_share` is specified, the final private key will also be
        reconstructed.
        """
        pass

    @abstractmethod
    def recover_nonce(self, self_k: int, z: List[int]) -> int:
        pass
