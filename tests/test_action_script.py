"""Testa .github/scripts/revisar_pr.sh num repositório git temporário (sem GitHub)."""

import os
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parent.parent / ".github" / "scripts" / "revisar_pr.sh"

SEGURO = "def soma(a, b):\n    return a + b\n"
VULNERAVEL = 'def buscar(conn, nome):\n    return conn.execute("SELECT * FROM t WHERE n = \'" + nome + "\'")\n'


def git(repo: Path, *args: str) -> str:
    env = {
        **os.environ,
        "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t",
        "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t",
    }
    return subprocess.run(
        ["git", *args], cwd=repo, env=env, check=True, capture_output=True, text=True
    ).stdout.strip()


@pytest.fixture
def pr(tmp_path):
    """Repositório com um commit base e um commit 'do PR' que adiciona app.py e tests/t.py vulneráveis."""
    git(tmp_path, "init", "-q", "-b", "main")
    (tmp_path / "ok.py").write_text(SEGURO)
    git(tmp_path, "add", "-A")
    git(tmp_path, "commit", "-q", "-m", "base")
    base = git(tmp_path, "rev-parse", "HEAD")

    (tmp_path / "app.py").write_text(VULNERAVEL)
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "t.py").write_text(VULNERAVEL)
    git(tmp_path, "add", "-A")
    git(tmp_path, "commit", "-q", "-m", "pr")
    return tmp_path, base, git(tmp_path, "rev-parse", "HEAD")


def rodar(repo: Path, base: str, head: str, **extra: str):
    # O `sentinela` instalado no mesmo ambiente do pytest precisa estar no PATH.
    ambiente = {
        "PATH": f"{Path(sys.executable).parent}{os.pathsep}{os.environ['PATH']}",
        "HOME": os.environ.get("HOME", ""),
        "BASE_SHA": base,
        "HEAD_SHA": head,
        **extra,
    }
    return subprocess.run(
        ["bash", str(SCRIPT)], cwd=repo, env=ambiente, capture_output=True, text=True
    )


def test_pr_com_vulnerabilidade_falha_e_gera_relatorio(pr):
    repo, base, head = pr

    r = rodar(repo, base, head)

    assert r.returncode == 1
    assert "<!-- sentinela -->" in r.stdout
    assert "SQL injection" in r.stdout and "`app.py:2`" in r.stdout
    assert (repo / "sentinela-relatorio.md").read_text() == r.stdout


def test_excluir_ignora_caminhos(pr):
    repo, base, head = pr

    r = rodar(repo, base, head, EXCLUIR="tests")

    assert "`tests/t.py" not in r.stdout and "`app.py:2`" in r.stdout


def test_excluir_tudo_passa(pr):
    repo, base, head = pr

    r = rodar(repo, base, head, EXCLUIR="app.py tests")

    assert r.returncode == 0
    assert "Nenhum problema" in r.stdout


def test_pr_sem_problemas_passa(tmp_path):
    git(tmp_path, "init", "-q", "-b", "main")
    (tmp_path / "a.py").write_text(SEGURO)
    git(tmp_path, "add", "-A")
    git(tmp_path, "commit", "-q", "-m", "base")
    base = git(tmp_path, "rev-parse", "HEAD")
    (tmp_path / "b.py").write_text(SEGURO)
    git(tmp_path, "add", "-A")
    git(tmp_path, "commit", "-q", "-m", "pr")

    r = rodar(tmp_path, base, git(tmp_path, "rev-parse", "HEAD"))

    assert r.returncode == 0


def test_commit_inexistente_falha_em_vez_de_passar_em_silencio(pr):
    repo, _, head = pr

    r = rodar(repo, "0" * 40, head)

    assert r.returncode == 2
    assert "fetch-depth: 0" in r.stdout


def test_fora_de_pull_request_da_erro_claro(tmp_path):
    r = subprocess.run(
        ["bash", str(SCRIPT)], cwd=tmp_path, env={"PATH": os.environ["PATH"]},
        capture_output=True, text=True,
    )

    assert r.returncode == 2
    assert "pull_request" in r.stdout
