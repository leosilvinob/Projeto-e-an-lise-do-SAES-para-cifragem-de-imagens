# Simplified AES Image Encryption Metrics

Este relatorio sumariza as metricas obtidas para cada modo de operacao do SAES.

## Medias por modo

| mode   |   entropy_mean |   corr_horizontal_mean |   corr_vertical_mean |   corr_diagonal_mean |   npcr_mean |   uaci_mean |
|:-------|---------------:|-----------------------:|---------------------:|---------------------:|------------:|------------:|
| CBC    |        7.9972  |           -3.32195e-05 |         -2.55873e-05 |          0.000935391 | 46.8857     | 8.86252     |
| CFB    |        7.99707 |            0.00204168  |         -0.00257048  |         -0.00244939  | 46.9109     | 8.84434     |
| CTR    |        7.99713 |           -0.000547373 |          0.456028    |          0.000468172 |  0.00152588 | 1.67547e-05 |
| ECB    |        7.83896 |           -0.000479486 |          0.208677    |          0.000301976 |  0.00305176 | 0.000610352 |
| OFB    |        7.9919  |           -0.00346056  |          0.0621599   |         -0.00294222  |  0.00152588 | 1.31644e-05 |

## Observacoes
- Entropias proximas de 8 indicam boa difusao em relacao ao espaco de niveis de cinza.
- Coeficientes de correlacao proximos de zero implicam quebra de dependencia entre pixels adjacentes.
- NPCR e UACI altos demonstram sensibilidade a pequenas alteracoes no plano original.
