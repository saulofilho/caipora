// Grade animada da Caipora: o título é desenhado com casas, e ondas em padrões
// (losango, zigue-zague, greca, trama) andam casa a casa, como um autômato.
(() => {
  const COR = {
    papel: '#F3EEE3', carvao: '#161412', linha: '#D8D0BF',
    jenipapo: '#1F2A44', urucum: '#D9481C', tabatinga: '#E0A526', mata: '#2F7D4F',
  };
  const PASSO_MS = 120;
  const parado = matchMedia('(prefers-reduced-motion: reduce)');

  const LETRAS = {
    C: ['.###.', '#...#', '#....', '#....', '#....', '#...#', '.###.'],
    A: ['.###.', '#...#', '#...#', '#####', '#...#', '#...#', '#...#'],
    I: ['#####', '..#..', '..#..', '..#..', '..#..', '..#..', '#####'],
    P: ['####.', '#...#', '#...#', '####.', '#....', '#....', '#....'],
    O: ['.###.', '#...#', '#...#', '#...#', '#...#', '#...#', '.###.'],
    R: ['####.', '#...#', '#...#', '####.', '#.#..', '#..#.', '#...#'],
  };
  const PALAVRA = 'CAIPORA';
  const LARGURA_PALAVRA = PALAVRA.length * 6 - 1;

  const mod = (n, m) => ((n % m) + m) % m;

  function preparar(canvas, cols, rows) {
    const dpr = window.devicePixelRatio || 1;
    const largura = canvas.clientWidth;
    const casa = largura / cols;
    const altura = casa * rows;
    canvas.style.height = altura + 'px';
    canvas.width = Math.round(largura * dpr);
    canvas.height = Math.round(altura * dpr);
    const ctx = canvas.getContext('2d');
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    return { ctx, casa, cols, rows };
  }

  function desenhar(g, corDe) {
    const { ctx, casa, cols, rows } = g;
    const fresta = casa > 14 ? 2 : 1;
    ctx.fillStyle = COR.linha;
    ctx.fillRect(0, 0, cols * casa, rows * casa);
    for (let y = 0; y < rows; y++) {
      for (let x = 0; x < cols; x++) {
        ctx.fillStyle = corDe(x, y);
        ctx.fillRect(x * casa + fresta / 2, y * casa + fresta / 2, casa - fresta, casa - fresta);
      }
    }
  }

  // ---------- grade do topo ----------
  const canvasTopo = document.getElementById('grade');
  const ANEL = [COR.papel, COR.papel, COR.papel, COR.tabatinga, COR.urucum, COR.jenipapo, COR.papel, COR.papel, COR.papel, COR.papel];
  const topo = { g: null, mascara: new Set(), caixa: null, origem: null, visivel: true };

  function montarTopo() {
    if (!canvasTopo) return;
    const largura = canvasTopo.clientWidth;
    const cols = Math.max(LARGURA_PALAVRA + 4, Math.min(64, Math.round(largura / 26)));
    const rows = Math.max(13, Math.round(cols * 0.42));
    topo.g = preparar(canvasTopo, cols, rows);
    topo.mascara.clear();
    const esquerda = Math.floor((cols - LARGURA_PALAVRA) / 2);
    const cima = Math.floor((rows - 7) / 2);
    // Margem limpa em volta do título: as ondas passam por fora e as letras ficam legíveis.
    topo.caixa = { x0: esquerda - 1, x1: esquerda + LARGURA_PALAVRA, y0: cima - 1, y1: cima + 7 };
    [...PALAVRA].forEach((letra, i) => {
      LETRAS[letra].forEach((linha, y) => {
        [...linha].forEach((px, x) => {
          if (px === '#') topo.mascara.add((cima + y) * cols + esquerda + i * 6 + x);
        });
      });
    });
    if (!topo.origem || topo.origem.x >= cols || topo.origem.y >= rows) {
      topo.origem = { x: Math.floor(cols / 2), y: rows - 2 };
    }
  }

  function desenharTopo(passo) {
    const { g, mascara, origem, caixa } = topo;
    desenhar(g, (x, y) => {
      if (mascara.has(y * g.cols + x)) return COR.carvao;
      if (x >= caixa.x0 && x <= caixa.x1 && y >= caixa.y0 && y <= caixa.y1) return COR.papel;
      const d = Math.abs(x - origem.x) + Math.abs(y - origem.y);
      return ANEL[mod(passo - d, ANEL.length)];
    });
  }

  if (canvasTopo) {
    canvasTopo.addEventListener('click', (ev) => {
      const r = canvasTopo.getBoundingClientRect();
      const casa = topo.g.casa;
      topo.origem = { x: Math.floor((ev.clientX - r.left) / casa), y: Math.floor((ev.clientY - r.top) / casa) };
      relogio.inicio = performance.now();
      if (parado.matches) desenharTopo(6);
    });
  }

  // ---------- padrões das seções ----------
  const PADROES = {
    losango: (x, y, p) => (mod(p - Math.round(Math.abs(x - 5.5) + Math.abs(y - 5.5)), 6) < 2 ? COR.jenipapo : COR.papel),
    zigue: (x, y, p) => (mod(p - (x + Math.abs(mod(y, 6) - 3) * 2), 6) < 2 ? COR.urucum : COR.papel),
    greca: (x, y, p) => (mod(p - Math.round(Math.max(Math.abs(x - 5.5), Math.abs(y - 5.5)) * 1.5), 6) < 2 ? COR.mata : COR.papel),
    trama: (x, y, p) => (mod(p + ((x + y) % 2) * 3 + (x % 4), 6) < 3 ? COR.tabatinga : COR.carvao),
  };
  const ladrilhos = [...document.querySelectorAll('canvas.padrao')].map((canvas) => ({
    canvas, regra: PADROES[canvas.dataset.padrao], g: null, visivel: false,
  }));

  function montarLadrilhos() {
    ladrilhos.forEach((l) => { l.g = preparar(l.canvas, 12, 12); });
  }

  // ---------- relógio ----------
  const relogio = { inicio: performance.now(), ultimo: -1, quadro: 0 };

  function tudo(passo) {
    if (topo.g && topo.visivel) desenharTopo(passo);
    ladrilhos.forEach((l) => { if (l.g && (l.visivel || parado.matches)) desenhar(l.g, (x, y) => l.regra(x, y, passo)); });
  }

  function animar(agora) {
    const passo = Math.floor((agora - relogio.inicio) / PASSO_MS);
    if (passo !== relogio.ultimo) {
      relogio.ultimo = passo;
      tudo(passo);
    }
    relogio.quadro = requestAnimationFrame(animar);
  }

  function iniciar() {
    cancelAnimationFrame(relogio.quadro);
    montarTopo();
    montarLadrilhos();
    if (parado.matches) {
      tudo(6); // um desenho parado, já com os anéis formados
    } else {
      relogio.ultimo = -1;
      relogio.quadro = requestAnimationFrame(animar);
    }
  }

  // Só anima o que está na tela.
  const olho = new IntersectionObserver((entradas) => {
    entradas.forEach((e) => {
      if (e.target === canvasTopo) topo.visivel = e.isIntersecting;
      const l = ladrilhos.find((item) => item.canvas === e.target);
      if (l) l.visivel = e.isIntersecting;
    });
  });
  if (canvasTopo) olho.observe(canvasTopo);
  ladrilhos.forEach((l) => olho.observe(l.canvas));

  let espera;
  new ResizeObserver(() => {
    clearTimeout(espera);
    espera = setTimeout(iniciar, 100);
  }).observe(document.body);
  parado.addEventListener('change', iniciar);
  iniciar();

  // ---------- elementos surgindo ao rolar ----------
  const surgir = new IntersectionObserver((entradas) => {
    entradas.forEach((e) => {
      if (e.isIntersecting) {
        e.target.classList.add('visivel');
        surgir.unobserve(e.target);
      }
    });
  }, { rootMargin: '0px 0px -10% 0px' });
  document.querySelectorAll('.surge').forEach((el) => surgir.observe(el));

  // ---------- copiar comandos ----------
  document.querySelectorAll('[data-copiar]').forEach((botao) => {
    botao.addEventListener('click', async () => {
      const texto = document.getElementById(botao.dataset.copiar).textContent;
      try {
        await navigator.clipboard.writeText(texto);
        botao.textContent = 'Copiado';
      } catch {
        botao.textContent = 'Selecione e copie';
      }
      setTimeout(() => { botao.textContent = 'Copiar'; }, 1800);
    });
  });
})();
