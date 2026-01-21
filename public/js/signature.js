
(function () {
  function qs(sel) { return document.querySelector(sel); }
  function qsa(sel) { return Array.from(document.querySelectorAll(sel)); }

  const form = qs('#sigForm');
  if (!form) return;

  const methodEl = qs('#method');
  const typedNameEl = qs('#typed_name');
  const typedStyleEl = qs('#typed_style');

  const sigOut = qs('#signature_data_url');
  const initOut = qs('#initials_data_url');

  const typedCanvas = qs('#typedCanvas');
  const typedCtx = typedCanvas.getContext('2d');

  const drawCanvas = qs('#drawCanvas');
  const drawCtx = drawCanvas.getContext('2d');

  const initialsWrap = qs('#initialsBoxWrap');
  const initialsCanvas = qs('#initialsCanvas');
  const initialsCtx = initialsCanvas ? initialsCanvas.getContext('2d') : null;

  const clearDrawBtn = qs('#clearDraw');
  const useDrawAsInitialsBtn = qs('#useDrawAsInitials');
  const clearInitialsBtn = qs('#clearInitials');

  // Tabs
  qsa('.tab').forEach(btn => {
    btn.addEventListener('click', () => {
      qsa('.tab').forEach(b => b.classList.remove('active'));
      qsa('.tab-panel').forEach(p => p.classList.remove('active'));
      btn.classList.add('active');
      const tab = btn.getAttribute('data-tab');
      qs('#tab-' + tab).classList.add('active');
      methodEl.value = tab === 'draw' ? 'drawn' : 'typed';
      // update outputs
      renderTyped();
    });
  });

  // Style buttons
  qsa('.sig-style').forEach(btn => {
    btn.addEventListener('click', () => {
      qsa('.sig-style').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      typedStyleEl.value = btn.getAttribute('data-style') || 'style1';
      renderTyped();
    });
  });

  function clearCanvas(ctx, canvas) {
    ctx.save();
    ctx.setTransform(1,0,0,1,0,0);
    ctx.clearRect(0,0,canvas.width, canvas.height);
    ctx.restore();
    // white background so PNG is clean
    ctx.fillStyle = '#ffffff';
    ctx.fillRect(0,0,canvas.width, canvas.height);
  }

  function getStyleFont(styleKey) {
    // Keep to 3 styles (as requested)
    if (styleKey === 'style2') return "64px 'Segoe Script','Lucida Handwriting',cursive";
    if (styleKey === 'style3') return "64px 'Lucida Handwriting','Comic Sans MS',cursive";
    return "64px 'Brush Script MT','Segoe Script',cursive";
  }

  function initialsFromName(name) {
    const parts = (name || '').trim().split(/\s+/).filter(Boolean);
    const first = parts[0]?.[0] || '';
    const last = parts.length > 1 ? parts[parts.length-1][0] : '';
    return (first + last).toUpperCase();
  }

  function renderTyped() {
    clearCanvas(typedCtx, typedCanvas);

    const name = (typedNameEl.value || '').trim();
    const styleKey = typedStyleEl.value || 'style1';

    // signature text
    typedCtx.fillStyle = '#111';
    typedCtx.font = getStyleFont(styleKey);
    typedCtx.textBaseline = 'middle';

    // fit long names
    let fontSize = 64;
    const targetWidth = typedCanvas.width - 80;
    while (fontSize > 36) {
      typedCtx.font = `${fontSize}px ` + getStyleFont(styleKey).split('px ')[1];
      const w = typedCtx.measureText(name || ' ').width;
      if (w <= targetWidth) break;
      fontSize -= 2;
    }

    typedCtx.fillText(name || ' ', 40, typedCanvas.height / 2);

    // initials (small)
    const inits = initialsFromName(name);
    // generate initials canvas image in-memory using typedCanvas area
    const initCanvas = document.createElement('canvas');
    initCanvas.width = 450;
    initCanvas.height = 180;
    const ictx = initCanvas.getContext('2d');
    clearCanvas(ictx, initCanvas);
    ictx.fillStyle = '#111';
    ictx.font = "72px 'Segoe Script','Brush Script MT',cursive";
    ictx.textBaseline = 'middle';
    ictx.fillText(inits || ' ', 40, initCanvas.height / 2);

    // Set outputs if typed mode
    if (methodEl.value === 'typed') {
      sigOut.value = typedCanvas.toDataURL('image/png');
      initOut.value = initCanvas.toDataURL('image/png');
    }
  }

  typedNameEl.addEventListener('input', renderTyped);

  // Draw signature pad
  function bindDrawing(canvas, ctx, onChange) {
    let drawing = false;
    let last = null;

    function getPos(e) {
      const rect = canvas.getBoundingClientRect();
      const touch = e.touches && e.touches[0];
      const clientX = touch ? touch.clientX : e.clientX;
      const clientY = touch ? touch.clientY : e.clientY;
      const x = (clientX - rect.left) * (canvas.width / rect.width);
      const y = (clientY - rect.top) * (canvas.height / rect.height);
      return { x, y };
    }

    function start(e) {
      drawing = true;
      last = getPos(e);
      e.preventDefault();
    }

    function move(e) {
      if (!drawing) return;
      const p = getPos(e);
      ctx.strokeStyle = '#111';
      ctx.lineWidth = 4;
      ctx.lineCap = 'round';
      ctx.beginPath();
      ctx.moveTo(last.x, last.y);
      ctx.lineTo(p.x, p.y);
      ctx.stroke();
      last = p;
      if (onChange) onChange();
      e.preventDefault();
    }

    function end(e) {
      drawing = false;
      last = null;
      if (onChange) onChange();
      e.preventDefault();
    }

    canvas.addEventListener('mousedown', start);
    canvas.addEventListener('mousemove', move);
    window.addEventListener('mouseup', end);

    canvas.addEventListener('touchstart', start, { passive: false });
    canvas.addEventListener('touchmove', move, { passive: false });
    window.addEventListener('touchend', end, { passive: false });
  }

  function initDrawPads() {
    clearCanvas(drawCtx, drawCanvas);
    bindDrawing(drawCanvas, drawCtx, () => {
      if (methodEl.value === 'drawn') sigOut.value = drawCanvas.toDataURL('image/png');
    });

    if (initialsCanvas && initialsCtx) {
      clearCanvas(initialsCtx, initialsCanvas);
      bindDrawing(initialsCanvas, initialsCtx, () => {
        if (methodEl.value === 'drawn') initOut.value = initialsCanvas.toDataURL('image/png');
      });
    }
  }

  if (clearDrawBtn) {
    clearDrawBtn.addEventListener('click', () => {
      clearCanvas(drawCtx, drawCanvas);
      if (methodEl.value === 'drawn') sigOut.value = '';
    });
  }

  if (useDrawAsInitialsBtn) {
    useDrawAsInitialsBtn.addEventListener('click', () => {
      initialsWrap.style.display = 'block';
    });
  }

  if (clearInitialsBtn && initialsCanvas && initialsCtx) {
    clearInitialsBtn.addEventListener('click', () => {
      clearCanvas(initialsCtx, initialsCanvas);
      if (methodEl.value === 'drawn') initOut.value = '';
    });
  }

  form.addEventListener('submit', (e) => {
    // Ensure correct output is set at submit time
    if (methodEl.value === 'typed') {
      renderTyped();
      if (!sigOut.value) {
        e.preventDefault();
        alert('Please type your name to generate a signature.');
      }
    } else {
      // drawn
      if (!sigOut.value) sigOut.value = drawCanvas.toDataURL('image/png');
      if (initialsCanvas && initialsWrap.style.display !== 'none') {
        if (!initOut.value) initOut.value = initialsCanvas.toDataURL('image/png');
      }
      // typed_name may not be required in drawn mode, but keep consistent
      if (!typedNameEl.value.trim()) typedNameEl.value = '(drawn signature)';
    }
  });

  // init
  initDrawPads();
  renderTyped();
})();
