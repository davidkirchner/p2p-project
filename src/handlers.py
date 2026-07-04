

from typing import Callable


class HandlerBase:
    def __init__(self, *overrides: Callable, **overrides_kw) -> None:
        for m in overrides:
            k = getattr(m, "__name__")
            setattr(self, k, m)
            
        for k, v in overrides_kw.items():
            setattr(self, k, v)