# Experimento de Cifragem SAES

Este documento resume a abordagem, implementação e análise empregadas para cifrar imagens utilizando o Simplified AES (SAES) em Python, seguindo as orientações dos artigos de referência.

## Abordagem Geral
- **Objetivo:** implementar o SAES, aplicar diversos modos de operação (ECB, CBC, CFB, OFB e CTR) em um conjunto de dez imagens em tons de cinza e avaliar quantitativamente/qualitativamente a eficácia de cada modo.
- **Referências utilizadas:**
  1. *Image encryption using block cipher and chaotic sequences* — Seção 3 (métricas de segurança) para fundamentar os quantificadores (entropia, correlação, NPCR, UACI) e as análises qualitativas via histograma.
  2. *Linear Cryptoanalysis of the Simplified AES Cipher Modified by Chaotic Sequences* — Até a Seção II.A para reforçar os detalhes do SAES (S-Box, operações de mistura, agendamento de chaves).
  3. *On the vulnerability of Simplified AES Algorithm Against Linear Cryptanalysis* — Até a Seção 3 para compreender limitações estruturais do SAES e contextualizar os resultados obtidos.

## Estrutura do Projeto
```
.
├── aes.py                # Implementação do SAES, modos, pipeline de imagens e cálculo das métricas
├── requirements.txt      # Dependências Python
├── report.md             # Este relatório
├── data/
│   └── prepared/         # 10 imagens 256x256 em escala de cinza (baixadas automaticamente)
└── outputs/
    ├── encrypted/<modo>/ # Imagens cifradas por modo
    ├── histograms/       # Histogramas antes/depois por imagem e modo
    ├── metrics_saes.csv  # Métricas detalhadas por imagem e modo
    └── metrics_summary.md# Médias por modo + notas interpretativas
```

## Implementação (resumo do `aes.py`)
1. **SAES Core** (`SimplifiedAES`):
   - Árvore de chave de 16 bits, S-Box/Inv S-Box 4x4, multiplicação em GF(2⁴) com polinômio $x^4 + x + 1$, e duas rodadas completas (AddRoundKey, SubNib, ShiftRows, MixColumns).
   - Funções auxiliares: `gf_mul`, `sub_nib`, `rot_nib`, conversão estado↔palavra e XOR byte a byte.
2. **Modos de operação** (`SAESModeProcessor`):
   - ECB (direto), CBC, CFB, OFB e CTR (contador de 16 bits) com IV/contador configurável.
3. **Métricas** (`shannon_entropy`, `adjacent_correlation`, `npcr`, `uaci`):
   - Seguem as definições de entropia de Shannon e coeficientes de correlação para vizinhanças horizontal/vertical/diagonal.
   - NPCR (Number of Pixels Change Rate) e UACI (Unified Average Changing Intensity) usados para medir sensibilidade a pequenas perturbações (delta unitário no pixel central).
4. **Pipeline** (`ImageEncryptionExperiment`):
   - Baixa 10 imagens determinísticas do Picsum (semente fixa), converte para 256×256 em escala de cinza.
   - Cifra cada imagem em todos os modos, salva histograma e imagem cifrada.
   - Consolida métricas em CSV e gera resumo em Markdown.

## Metodologia
1. **Pré-processamento**: todas as imagens foram redimensionadas e convertidas para tons de cinza. Isso garante uniformidade para comparação e evita efeitos decorrentes de múltiplos canais.
2. **Chave fixa**: `0x3A94` para todos os modos. IVs/contadores distintos evitam a reutilização de vetores sem relação com cada modo.
3. **Perturbação mínima**: para NPCR/UACI, um único pixel central sofre incremento circular de +1, refletindo a sensibilidade do modo à pequena alteração.
4. **Coleta das métricas**: resultados individuais são armazenados em `outputs/metrics_saes.csv`, enquanto `outputs/metrics_summary.md` contém médias por modo.

## Resultados Quantitativos (médias por modo)
| modo | entropia | corr. horizontal | corr. vertical | corr. diagonal | NPCR (%) | UACI (%) |
|------|----------|------------------|----------------|----------------|----------|----------|
| CBC  | 7.9972   | -3.3e-05         | -2.6e-05       | 9.35e-04       | 46.89    | 8.86     |
| CFB  | 7.9971   | 2.0e-03          | -2.6e-03       | -2.4e-03       | 46.91    | 8.84     |
| CTR  | 7.9971   | -5.5e-04         | **0.456**      | 4.68e-04       | ~0.0015  | 1.68e-05 |
| ECB  | 7.8390   | -4.8e-04         | **0.209**      | 3.02e-04       | ~0.0031  | 0.00061  |
| OFB  | 7.9919   | -3.5e-03         | 0.0622         | -2.9e-03       | ~0.0015  | 1.32e-05 |

*(valores provenientes de `outputs/metrics_summary.md`)*  

## Discussão e Conclusões
1. **Entropia**: CBC, CFB e CTR alcançaram valores médios muito próximos de 8 bits, confirmando distribuição quase uniforme de pixels cifrados. ECB ficou abaixo, revelando que blocos idênticos ainda produzem padrões visíveis devido ao pequeno tamanho de bloco do SAES (16 bits).
2. **Correlação**:
   - **CBC/CFB**: coeficientes horizontais/verticais próximos de zero, indicando perda da dependência linear entre pixels adjacentes.
   - **CTR**: entropia alta, mas correlação vertical ≈ 0.46. A combinação do modo CTR com blocos de 2 bytes facilita a preservação de padrões lineares (mesma stream key para pares consecutivos), deixando estruturas verticais reconhecíveis.
   - **ECB**: correlação vertical ≈ 0.21, reforçando a baixa difusão do modo em ciphers com blocos curtos.
3. **NPCR/UACI**:
   - CBC/CFB alcançaram NPCR ~47% e UACI ~8.85%, demonstrando boa sensibilidade a pequenas variações na imagem original. Esses valores, embora menores do que os típicos de AES real (≈99% e ≈33%), são coerentes com a limitação estrutural do SAES descrita nos artigos 2 e 3.
   - ECB/OFB/CTR apresentaram NPCR e UACI praticamente nulos porque a alteração de um único pixel impacta apenas um bloco de 16 bits. Sem realimentação do cifrador, o efeito não se propaga pelos demais blocos.
4. **Histogramas** (`outputs/histograms/`): visivelmente, os modos com feedback (CBC, CFB) espalham os níveis de cinza de forma uniforme, criando histogramas quase planos. ECB preserva picos semelhantes ao original, enquanto CTR mostra padrão intermediário graças ao contador determinístico.

### Justificativa dos Resultados
- O SAES foi concebido apenas para fins didáticos, possuindo bloco pequeno e poucas rodadas, o que reduz difusão/confusão. Assim, mesmo com modos modernos, os quantificadores não atingem níveis de cifras industriais, concordando com as vulnerabilidades discutidas no artigo 3.
- Modos com realimentação (CBC/CFB) distribuem erros e propagam dependências com o IV, garantindo maior quebra de correlação e maior NPCR/UACI, como esperado teoricamente (artigo 1).
- Modos sem realimentação ou com realimentação limitada (ECB/OFB/CTR) mantêm relações entre blocos consecutivos, o que explica as correlações residuais e a baixa sensibilidade a perturbações. O artigo 2 destaca exatamente esse tipo de fraqueza quando o SAES é usado em cenários com baixa entropia na entrada.
- Portanto, embora todos os modos produzam entropia alta (por causa da S-Box e permutações), apenas CBC/CFB atingem níveis razoáveis de NPCR/UACI para imagens, demonstrando quantitativa e qualitativamente a importância dos modos de operação na cifragem.

## Como Reproduzir
1. Instale as dependências: `pip install -r requirements.txt`
2. Execute: `python aes.py`
3. Analise os resultados em `outputs/` e os histogramas correspondentes.

Esse fluxo gera automaticamente as imagens, métricas e justificativas necessárias para o relatório final.
