from pathlib import Path

from sentinela.config import Config, carregar


def test_sem_arquivo_e_o_padrao(tmp_path):
    assert carregar(tmp_path) == Config()


def test_le_regras_desativadas_e_ignorar(tmp_path):
    (tmp_path / ".sentinela.toml").write_text(
        '[regras]\ndesativar = ["segredo-url-com-senha", "tls-sem-verificacao"]\n\n'
        '[varrer]\nignorar = ["migrations/", "*.generated.ts"]\n',
        encoding="utf-8",
    )

    config = carregar(tmp_path)

    assert config.regras_desativadas == {"segredo-url-com-senha", "tls-sem-verificacao"}
    assert config.ignorar == ("migrations/", "*.generated.ts")
    assert config.erro is None


def test_so_a_secao_regras_sem_varrer_funciona(tmp_path):
    (tmp_path / ".sentinela.toml").write_text('[regras]\ndesativar = ["tls-sem-verificacao"]\n', encoding="utf-8")

    config = carregar(tmp_path)

    assert config.regras_desativadas == {"tls-sem-verificacao"}
    assert config.ignorar == ()


def test_sintaxe_invalida_nao_quebra_e_avisa(tmp_path):
    (tmp_path / ".sentinela.toml").write_text("isto não é toml válido [[[", encoding="utf-8")

    config = carregar(tmp_path)

    assert config == Config()  # Config.erro não entra na comparação (compare=False)
    assert config.erro is not None


def test_campo_no_formato_errado_cai_pro_padrao_e_avisa(tmp_path):
    (tmp_path / ".sentinela.toml").write_text('[regras]\ndesativar = "nao-e-uma-lista"\n', encoding="utf-8")

    config = carregar(tmp_path)

    assert config.regras_desativadas == frozenset()
    assert config.erro is not None
