"""
Experimento de cifragem de imagens usando o Simplified AES (SAES).

O modulo implementa o SAES, os principais modos de operacao por blocos e um
pipeline que baixa dez imagens em tons de cinza, cifra cada uma nos modos
selecionados, calcula metricas de seguranca quantitativas e gera relatorios
visuais/tabelas para analise.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from io import BytesIO
from pathlib import Path
from typing import Dict, Iterable, List, Tuple

import matplotlib
import numpy as np
import pandas as pd
import requests
from PIL import Image

matplotlib.use("Agg")
import matplotlib.pyplot as plt


# Caixas S e inversa especificas do SAES (opera sobre nibbles de 4 bits)
SBOX = [
    0x9,
    0x4,
    0xA,
    0xB,
    0xD,
    0x1,
    0x8,
    0x5,
    0x6,
    0x2,
    0x0,
    0x3,
    0xC,
    0xE,
    0xF,
    0x7,
]

INV_SBOX = [
    0xA,
    0x5,
    0x9,
    0xB,
    0x1,
    0x7,
    0x8,
    0xF,
    0x6,
    0x0,
    0x2,
    0x3,
    0xC,
    0x4,
    0xD,
    0xE,
]

RCON = (0x80, 0x30)

# Matrizes da etapa MixColumns (e inversa) no corpo finito GF(2^4)
MIX_COL_MATRIX = ((1, 4), (4, 1))
INV_MIX_COL_MATRIX = ((9, 2), (2, 9))


def gf_mul(a: int, b: int) -> int:
    """Multiplica dois valores de 4 bits em GF(2^4) com o polinomio x^4 + x + 1."""

    p = 0
    for _ in range(4):
        if b & 1:
            p ^= a  # acumula termo quando bit correspondente estiver ativo
        carry = a & 0x8
        a = (a << 1) & 0xF
        if carry:
            a ^= 0x3  # aplica reducao pelo polinomio irreducivel
        b >>= 1
    return p & 0xF


def sub_nib(byte: int) -> int:
    return (SBOX[(byte >> 4) & 0xF] << 4) | SBOX[byte & 0xF]


def rot_nib(byte: int) -> int:
    return ((byte << 4) | (byte >> 4)) & 0xFF


def state_from_word(word: int) -> List[List[int]]:
    """Transforma um bloco de 16 bits em matriz 2x2 de nibbles."""
    return [
        [(word >> 12) & 0xF, (word >> 8) & 0xF],
        [(word >> 4) & 0xF, word & 0xF],
    ]


def word_from_state(state: List[List[int]]) -> int:
    """Converte a matriz 2x2 de nibbles de volta para inteiro de 16 bits."""
    return (
        (state[0][0] << 12)
        | (state[0][1] << 8)
        | (state[1][0] << 4)
        | state[1][1]
    )


class SimplifiedAES:
    """Implementacao do SAES conforme a definicao classica de Stallings."""

    block_size = 2  # tamanho em bytes

    def __init__(self, key: bytes):
        if len(key) != 2:
            raise ValueError("SAES requires a 16-bit key (2 bytes).")
        self.key = int.from_bytes(key, "big")
        self.round_keys = self._key_schedule(self.key)  # gera as tres chaves de rodada

    @staticmethod
    def _key_schedule(key: int) -> Tuple[int, int, int]:
        """Gera as tres subchaves de 16 bits usadas nas rodadas do SAES."""
        w0 = (key >> 8) & 0xFF
        w1 = key & 0xFF
        w2 = w0 ^ RCON[0] ^ sub_nib(rot_nib(w1))
        w3 = w2 ^ w1
        w4 = w2 ^ RCON[1] ^ sub_nib(rot_nib(w3))
        w5 = w4 ^ w3
        k0 = (w0 << 8) | w1
        k1 = (w2 << 8) | w3
        k2 = (w4 << 8) | w5
        return (k0, k1, k2)

    @staticmethod
    def _sub_nibbles(state: List[List[int]], inverse: bool = False) -> List[List[int]]:
        """Aplica S-Box (ou inversa) em cada nibble do estado."""
        lookup = INV_SBOX if inverse else SBOX
        return [[lookup[nibble] for nibble in row] for row in state]

    @staticmethod
    def _shift_rows(state: List[List[int]], inverse: bool = False) -> List[List[int]]:
        """Rotaciona a segunda linha para introduzir dispersao."""
        top_row = state[0][:]
        bottom_row = state[1][:]
        if inverse:
            bottom_row = [bottom_row[1], bottom_row[0]]
        else:
            bottom_row = [bottom_row[1], bottom_row[0]]
        return [top_row, bottom_row]

    @staticmethod
    def _mix_columns(
        state: List[List[int]], matrix: Tuple[Tuple[int, int], Tuple[int, int]]
    ) -> List[List[int]]:
        """Mistura as colunas via multiplicacao matricial no campo GF(2^4)."""
        col0 = [state[0][0], state[1][0]]
        col1 = [state[0][1], state[1][1]]
        new_col0 = [
            gf_mul(matrix[0][0], col0[0]) ^ gf_mul(matrix[0][1], col0[1]),
            gf_mul(matrix[1][0], col0[0]) ^ gf_mul(matrix[1][1], col0[1]),
        ]
        new_col1 = [
            gf_mul(matrix[0][0], col1[0]) ^ gf_mul(matrix[0][1], col1[1]),
            gf_mul(matrix[1][0], col1[0]) ^ gf_mul(matrix[1][1], col1[1]),
        ]
        return [[new_col0[0], new_col1[0]], [new_col0[1], new_col1[1]]]

    @staticmethod
    def _add_round_key(state: List[List[int]], round_key: int) -> List[List[int]]:
        """Aplica XOR do estado com a subchave da rodada."""
        key_state = state_from_word(round_key)
        return [
            [
                state[0][0] ^ key_state[0][0],
                state[0][1] ^ key_state[0][1],
            ],
            [
                state[1][0] ^ key_state[1][0],
                state[1][1] ^ key_state[1][1],
            ],
        ]

    def encrypt_block(self, block: bytes) -> bytes:
        if len(block) != self.block_size:
            raise ValueError("Invalid block length.")
        word = int.from_bytes(block, "big")
        state = state_from_word(word)
        # Estrutura: AddRoundKey -> (SubBytes, ShiftRows, MixColumns) -> AddRoundKey -> (SubBytes, ShiftRows) -> AddRoundKey
        state = self._add_round_key(state, self.round_keys[0])
        state = self._sub_nibbles(state)
        state = self._shift_rows(state)
        state = self._mix_columns(state, MIX_COL_MATRIX)
        state = self._add_round_key(state, self.round_keys[1])
        state = self._sub_nibbles(state)
        state = self._shift_rows(state)
        state = self._add_round_key(state, self.round_keys[2])
        encrypted = word_from_state(state)
        return encrypted.to_bytes(self.block_size, "big")

    def decrypt_block(self, block: bytes) -> bytes:
        if len(block) != self.block_size:
            raise ValueError("Invalid block length.")
        word = int.from_bytes(block, "big")
        state = state_from_word(word)
        # Aplica a sequencia inversa das operacoes de cifragem
        state = self._add_round_key(state, self.round_keys[2])
        state = self._shift_rows(state, inverse=True)
        state = self._sub_nibbles(state, inverse=True)
        state = self._add_round_key(state, self.round_keys[1])
        state = self._mix_columns(state, INV_MIX_COL_MATRIX)
        state = self._shift_rows(state, inverse=True)
        state = self._sub_nibbles(state, inverse=True)
        state = self._add_round_key(state, self.round_keys[0])
        decrypted = word_from_state(state)
        return decrypted.to_bytes(self.block_size, "big")


def chunk_data(data: bytes, size: int) -> Iterable[bytes]:
    """Divide um buffer em blocos do tamanho especificado."""
    if len(data) % size != 0:
        raise ValueError("Data length must be a multiple of block size.")
    for idx in range(0, len(data), size):
        yield data[idx : idx + size]


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """Aplica XOR byte a byte entre duas sequencias."""
    return bytes(x ^ y for x, y in zip(a, b))


@dataclass(frozen=True)
class ModeConfig:
    """Representa parametros essenciais de um modo de cifragem."""
    name: str
    iv: bytes | None = None
    counter: int = 0


class SAESModeProcessor:
    """Aplica o SAES nos diferentes modos de operacao por blocos."""

    def __init__(self, key: bytes, config: ModeConfig):
        self.cipher = SimplifiedAES(key)
        self.config = config

    def encrypt(self, data: bytes) -> bytes:
        mode = self.config.name.upper()
        if mode == "ECB":
            return self._ecb_encrypt(data)
        if mode == "CBC":
            return self._cbc_encrypt(data)
        if mode == "CFB":
            return self._cfb_encrypt(data)
        if mode == "OFB":
            return self._ofb_encrypt(data)
        if mode == "CTR":
            return self._ctr_process(data)
        raise ValueError(f"Unsupported mode {self.config.name}")

    def _ecb_encrypt(self, data: bytes) -> bytes:
        blocks = []
        for block in chunk_data(data, self.cipher.block_size):
            blocks.append(self.cipher.encrypt_block(block))
        return b"".join(blocks)

    def _cbc_encrypt(self, data: bytes) -> bytes:
        if not self.config.iv:
            raise ValueError("CBC mode requires an IV.")
        prev = self.config.iv
        result = []
        for block in chunk_data(data, self.cipher.block_size):
            xored = xor_bytes(block, prev)  # mistura bloco com IV/cifra anterior
            cipher_block = self.cipher.encrypt_block(xored)
            result.append(cipher_block)
            prev = cipher_block  # retroalimentacao
        return b"".join(result)

    def _cfb_encrypt(self, data: bytes) -> bytes:
        if not self.config.iv:
            raise ValueError("CFB mode requires an IV.")
        prev = self.config.iv
        output = []
        for block in chunk_data(data, self.cipher.block_size):
            keystream = self.cipher.encrypt_block(prev)  # gera fluxo usando cifra anterior
            cipher_block = xor_bytes(block, keystream)
            output.append(cipher_block)
            prev = cipher_block
        return b"".join(output)

    def _ofb_encrypt(self, data: bytes) -> bytes:
        if not self.config.iv:
            raise ValueError("OFB mode requires an IV.")
        feedback = self.config.iv
        output = []
        for block in chunk_data(data, self.cipher.block_size):
            feedback = self.cipher.encrypt_block(feedback)  # fluxo independente do texto claro
            output.append(xor_bytes(block, feedback))
        return b"".join(output)

    def _ctr_process(self, data: bytes) -> bytes:
        counter = self.config.counter
        output = []
        for block in chunk_data(data, self.cipher.block_size):
            counter_block = counter.to_bytes(self.cipher.block_size, "big")
            keystream = self.cipher.encrypt_block(counter_block)
            output.append(xor_bytes(block, keystream))
            counter = (counter + 1) & 0xFFFF  # incrementa contador modular de 16 bits
        return b"".join(output)


def shannon_entropy(image: np.ndarray) -> float:
    """Calcula a entropia de Shannon (em bits) dos niveis de cinza."""
    histogram, _ = np.histogram(image.flatten(), bins=256, range=(0, 256))
    probabilities = histogram / histogram.sum()
    probabilities = probabilities[probabilities > 0]
    return float(-(probabilities * np.log2(probabilities)).sum())


def adjacent_correlation(image: np.ndarray, direction: str) -> float:
    """Obtém correlacao entre pixels adjacentes em direcoes especificas."""
    if direction == "horizontal":
        x = image[:, :-1].flatten()
        y = image[:, 1:].flatten()
    elif direction == "vertical":
        x = image[:-1, :].flatten()
        y = image[1:, :].flatten()
    elif direction == "diagonal":
        x = image[:-1, :-1].flatten()
        y = image[1:, 1:].flatten()
    else:
        raise ValueError("Invalid direction.")
    if x.size == 0 or y.size == 0:
        return 0.0
    x = x.astype(np.float64)
    y = y.astype(np.float64)
    std_x = np.std(x)
    std_y = np.std(y)
    if std_x == 0 or std_y == 0:
        return 0.0
    cov = np.mean((x - x.mean()) * (y - y.mean()))
    return float(cov / (std_x * std_y))


def npcr(original: np.ndarray, test: np.ndarray) -> float:
    """Calcula o Percentage of Number of Pixels Change Rate entre duas imagens."""
    diff = np.not_equal(original, test)
    return float(diff.sum() * 100 / diff.size)


def uaci(original: np.ndarray, test: np.ndarray) -> float:
    """Calcula o Unified Average Changing Intensity (variacao media percentual)."""
    diff = np.abs(original.astype(np.float64) - test.astype(np.float64))
    return float(diff.sum() * 100 / (diff.size * 255))


def save_histogram(original: np.ndarray, encrypted: np.ndarray, title: str, path: Path):
    """Salva histograma comparando distribuicoes do original e cifrado."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fig, axes = plt.subplots(1, 2, figsize=(10, 4))
    axes[0].hist(original.flatten(), bins=256, range=(0, 255), color="steelblue")
    axes[0].set_title("Original")
    axes[1].hist(encrypted.flatten(), bins=256, range=(0, 255), color="firebrick")
    axes[1].set_title("Cifrada")
    fig.suptitle(title)
    fig.tight_layout()
    fig.savefig(path, dpi=200)
    plt.close(fig)


IMAGE_SPECS = [
    ("cactus", "https://picsum.photos/seed/cactus/256/256"),
    ("city", "https://picsum.photos/seed/cityscape/256/256"),
    ("forest", "https://picsum.photos/seed/forestpath/256/256"),
    ("harbor", "https://picsum.photos/seed/harbor/256/256"),
    ("mountain", "https://picsum.photos/seed/mountain/256/256"),
    ("desert", "https://picsum.photos/seed/desert/256/256"),
    ("bridge", "https://picsum.photos/seed/bridge/256/256"),
    ("wildlife", "https://picsum.photos/seed/wildlife/256/256"),
    ("architecture", "https://picsum.photos/seed/architecture/256/256"),
    ("texture", "https://picsum.photos/seed/texture/256/256"),
]  # Dez imagens deterministicas para manter o conjunto reproduzivel.


class ImageEncryptionExperiment:
    """Orquestra o fluxo completo de preparo das imagens e avaliacao dos modos."""
    def __init__(self):
        # Diretorios de trabalho e saida
        self.base_dir = Path(__file__).parent
        self.data_dir = self.base_dir / "data"
        self.source_dir = self.data_dir / "source"
        self.prepared_dir = self.data_dir / "prepared"
        self.output_dir = self.base_dir / "outputs"
        self.encrypted_dir = self.output_dir / "encrypted"
        self.hist_dir = self.output_dir / "histograms"
        self.table_path = self.output_dir / "metrics_saes.csv"
        self.summary_path = self.output_dir / "metrics_summary.md"
        self.size = (256, 256)
        key_hex = "3A94"
        self.key = bytes.fromhex(key_hex)
        # Configuracao fixa dos modos utilizados no experimento
        self.mode_configs: Dict[str, ModeConfig] = {
            "ECB": ModeConfig("ECB"),
            "CBC": ModeConfig("CBC", iv=bytes.fromhex("BEEF")),
            "CFB": ModeConfig("CFB", iv=bytes.fromhex("1234")),
            "OFB": ModeConfig("OFB", iv=bytes.fromhex("ACDC")),
            "CTR": ModeConfig("CTR", counter=0x1F1F),
        }

    def prepare_environment(self):
        """Garante que toda a estrutura de diretorios exista antes do processamento."""
        for directory in [
            self.source_dir,
            self.prepared_dir,
            self.output_dir,
            self.encrypted_dir,
            self.hist_dir,
        ]:
            directory.mkdir(parents=True, exist_ok=True)

    def download_images(self):
        """Baixa e normaliza as dez imagens caso ainda nao existam."""
        for name, url in IMAGE_SPECS:
            final_path = self.prepared_dir / f"{name}.png"
            if final_path.exists():
                continue
            response = requests.get(url, timeout=30)
            response.raise_for_status()
            image = Image.open(BytesIO(response.content)).convert("L")
            image = image.resize(self.size)
            image.save(final_path)

    def load_images(self) -> List[Tuple[str, Path]]:
        images = []
        for path in sorted(self.prepared_dir.glob("*.png")):
            images.append((path.stem, path))
        if len(images) < 10:
            raise RuntimeError("Expected ten images after preparation.")
        return images

    def run(self):
        """Executa todo o pipeline: prepara, cifra, mede e salva resultados."""
        self.prepare_environment()
        self.download_images()
        images = self.load_images()
        self.encrypted_dir.mkdir(parents=True, exist_ok=True)
        metrics_rows = []
        modified_delta = 1
        for mode_name, config in self.mode_configs.items():
            processor = SAESModeProcessor(self.key, config)
            mode_dir = self.encrypted_dir / mode_name.lower()
            mode_dir.mkdir(parents=True, exist_ok=True)
            for image_name, image_path in images:
                original_img = Image.open(image_path).convert("L")
                original_arr = np.array(original_img, dtype=np.uint8)
                encrypted_arr = self._encrypt_array(processor, original_arr)
                encrypted_img = Image.fromarray(encrypted_arr, mode="L")
                encrypted_path = mode_dir / f"{image_name}_{mode_name}.png"
                encrypted_img.save(encrypted_path)

                metrics = self._compute_metrics(
                    image_name, mode_name, original_arr, encrypted_arr, processor, modified_delta
                )
                metrics_rows.append(metrics)

                hist_path = self.hist_dir / f"{image_name}_{mode_name}.png"
                save_histogram(
                    original_arr,
                    encrypted_arr,
                    f"{image_name} - {mode_name}",
                    hist_path,
                )

        df = pd.DataFrame(metrics_rows)
        df.to_csv(self.table_path, index=False)
        self._save_markdown_summary(df)

    @staticmethod
    def _encrypt_array(processor: SAESModeProcessor, array: np.ndarray) -> np.ndarray:
        """Aplica o modo desejado a uma matriz numpy tratando-a como fluxo de bytes."""
        data = array.tobytes()
        encrypted_bytes = processor.encrypt(data)
        encrypted_arr = np.frombuffer(encrypted_bytes, dtype=np.uint8).reshape(array.shape)
        return encrypted_arr

    def _compute_metrics(
        self,
        image_name: str,
        mode_name: str,
        original: np.ndarray,
        encrypted: np.ndarray,
        processor: SAESModeProcessor,
        delta: int,
    ) -> Dict[str, float | str]:
        """Calcula todas as metricas de seguranca para uma imagem/modo."""
        altered = original.copy()
        center = (altered.shape[0] // 2, altered.shape[1] // 2)
        altered_val = int(altered[center])
        altered[center] = (altered_val + delta) % 256
        altered_encrypted = self._encrypt_array(processor, altered)

        record = {
            "image": image_name,
            "mode": mode_name,
            "entropy": shannon_entropy(encrypted),
            "corr_horizontal": adjacent_correlation(encrypted, "horizontal"),
            "corr_vertical": adjacent_correlation(encrypted, "vertical"),
            "corr_diagonal": adjacent_correlation(encrypted, "diagonal"),
            "npcr": npcr(encrypted, altered_encrypted),
            "uaci": uaci(encrypted, altered_encrypted),
        }
        return record

    def _save_markdown_summary(self, df: pd.DataFrame):
        """Gera resumo estatistico dos modos e inclui observacoes qualitativas."""
        self.summary_path.parent.mkdir(parents=True, exist_ok=True)
        averages = (
            df.groupby("mode")
            .agg(
                entropy_mean=("entropy", "mean"),
                corr_horizontal_mean=("corr_horizontal", "mean"),
                corr_vertical_mean=("corr_vertical", "mean"),
                corr_diagonal_mean=("corr_diagonal", "mean"),
                npcr_mean=("npcr", "mean"),
                uaci_mean=("uaci", "mean"),
            )
            .reset_index()
        )
        with self.summary_path.open("w", encoding="utf-8") as md:
            md.write("# Metricas de Cifragem com SAES\n\n")
            md.write("Este relatorio sumariza as metricas obtidas para cada modo de operacao do SAES.\n\n")
            md.write("## Medias por modo\n\n")
            md.write(averages.to_markdown(index=False))
            md.write("\n\n")
            md.write(
                "## Observacoes\n"
                "- Entropias proximas de 8 indicam boa difusao em relacao ao espaco de niveis de cinza.\n"
                "- Coeficientes de correlacao proximos de zero implicam quebra de dependencia entre pixels adjacentes.\n"
                "- NPCR e UACI altos demonstram sensibilidade a pequenas alteracoes no plano original.\n"
            )


if __name__ == "__main__":
    experiment = ImageEncryptionExperiment()
    experiment.run()
