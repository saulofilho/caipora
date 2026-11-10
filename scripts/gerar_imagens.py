"""Gera as imagens do site e do README a partir da mesma grade do topo do site.

    uv run --no-project --with pillow python scripts/gerar_imagens.py

Saídas em docs/img/: compartilhar.png (1200x630, Open Graph), banner.png (README).
"""

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

PAPEL, CARVAO, LINHA = "#F3EEE3", "#161412", "#D8D0BF"
JENIPAPO, URUCUM, TABATINGA = "#1F2A44", "#D9481C", "#E0A526"
ANEL = [PAPEL, PAPEL, PAPEL, TABATINGA, URUCUM, JENIPAPO, PAPEL, PAPEL, PAPEL, PAPEL]
LETRAS = {
    "C": [".###.", "#...#", "#....", "#....", "#....", "#...#", ".###."],
    "A": [".###.", "#...#", "#...#", "#####", "#...#", "#...#", "#...#"],
    "I": ["#####", "..#..", "..#..", "..#..", "..#..", "..#..", "#####"],
    "P": ["####.", "#...#", "#...#", "####.", "#....", "#....", "#...."],
    "O": [".###.", "#...#", "#...#", "#...#", "#...#", "#...#", ".###."],
    "R": ["####.", "#...#", "#...#", "####.", "#.#..", "#..#.", "#...#"],
}
FONTE = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
SAIDA = Path(__file__).resolve().parent.parent / "docs" / "img"


def grade(cols: int, rows: int, casa: int, passo: int, origem: tuple[int, int], topo: int) -> Image.Image:
    img = Image.new("RGB", (cols * casa, rows * casa), LINHA)
    d = ImageDraw.Draw(img)
    esquerda = (cols - 41) // 2
    mascara = {
        (topo + y, esquerda + i * 6 + x)
        for i, letra in enumerate("CAIPORA")
        for y, linha in enumerate(LETRAS[letra])
        for x, px in enumerate(linha)
        if px == "#"
    }
    for y in range(rows):
        for x in range(cols):
            if (y, x) in mascara:
                cor = CARVAO
            elif topo - 1 <= y <= topo + 7 and esquerda - 1 <= x <= esquerda + 41:
                cor = PAPEL  # margem limpa em volta do título, para ele ficar legível
            else:
                dist = abs(x - origem[0]) + abs(y - origem[1])
                cor = ANEL[(passo - dist) % len(ANEL)]
            d.rectangle([x * casa + 1, y * casa + 1, (x + 1) * casa - 2, (y + 1) * casa - 2], fill=cor)
    return img


def compartilhar() -> None:
    img = Image.new("RGB", (1200, 630), PAPEL)
    g = grade(cols=47, rows=19, casa=24, passo=14, origem=(23, 17), topo=4)
    img.paste(g, ((1200 - g.width) // 2, 40))
    d = ImageDraw.Draw(img)
    fonte = ImageFont.truetype(FONTE, 30)
    d.text((600, 540), "red teaming de IA em português", font=fonte, fill=CARVAO, anchor="mm")
    fonte_peq = ImageFont.truetype(FONTE, 20)
    d.text((600, 584), "chatbots · agentes · servidores MCP · CI", font=fonte_peq, fill="#4A453D", anchor="mm")
    img.save(SAIDA / "compartilhar.png", optimize=True)


def banner() -> None:
    g = grade(cols=61, rows=15, casa=26, passo=12, origem=(30, 13), topo=4)
    g.save(SAIDA / "banner.png", optimize=True)


if __name__ == "__main__":
    SAIDA.mkdir(parents=True, exist_ok=True)
    compartilhar()
    banner()
    print(f"imagens em {SAIDA}")
