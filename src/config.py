from dataclasses import dataclass
import os
from typing import Self
from pathlib import Path

@dataclass(unsafe_hash=True)
class Config:
    
    sqlite_path: Path
    
    @classmethod
    def from_env(cls, prefix: str = "") -> Self:
        path = os.environ.get(prefix + "SQLITE_PATH")
        if path is None:
            path = Path("var", "db", "db.sqlite")
        else:
            path = Path(path)
            
        return cls(
            sqlite_path=path
        )