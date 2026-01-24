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
  const drawCanvas = qs('#drawCanvas');

  if (!methodEl || !typedNameEl || !typedStyleEl || !sigOut || !initOut || !typedCanvas || !drawCanvas) return;

  const typedCtx = typedCanvas.getContext('2d');
  const drawCtx = drawCanvas.getContext('2d');

  const initialsWrap = qs('#initialsBoxWrap');
  const initialsCanvas = qs('#initialsCanvas');
  const initialsCtx = initialsCanvas ? initialsCanvas.getContext('2d') : null;

  const clearDrawBtn = qs('#clearDraw');
  const useDrawAsInitialsBtn = qs('#useDrawAsInitials');
  const clearInitialsBtn = qs('#clearInitials');

  // ----------------------------
  // Mode helpers / normalization
  // ----------------------------
  function normalizeMethod() {
    // Accept old + new values safely; normalize draw to "drawn"
    const v = (methodEl.value || '').toLowerCase().trim();
    if (v === 'draw') methodEl.value = 'drawn';
    if (v !== 'typed' && v !== 'drawn') methodEl.value = 'typed';
  }

  function isTypedMode() {
    normalizeMethod();
    return methodEl.value === 'typed';
  }

  function isDrawnMode() {
    normalizeMethod();
    return methodEl.value === 'drawn';
  }

  // ----------------------------
  // Canvas utilities (transparent PNG)
  // ----------------------------
  function clearCanvas(ctx, canvas) {
    ctx.save();
    ctx.setTransform(1, 0, 0, 1, 0, 0);
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    ctx.restore();
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
    const last = parts.length > 1 ? parts[parts.length - 1][0] : '';
    return (first + last).toUpperCase();
  }

  // ----------------------------
  // Typed signature rendering
  // ----------------------------
  function renderTyped() {
    clearCanvas(typedCtx, typedCanvas);

    const name = (typedNameEl.value || '').trim();
    const styleKey = (typedStyleEl.value || 'style1').trim();

    // Signature text
    typedCtx.fillStyle = '#111';
    typedCtx.textBaseline = 'middle';

    // Fit long names
    let fontSize = 64;
    const family = getStyleFont(styleKey).split('px ')[1]; // everything after "64px "
    const targetWidth = typedCanvas.width - 80;

    while (fontSize > 30) {
      typedCtx.font = `${fontSize}px ${family}`;
      const w = typedCtx.measureText(name || ' ').width;
      if (w <= targetWidth) break;
      fontSize -= 2;
    }

    typedCtx.fillText(name || ' ', 40, typedCanvas.height / 2);

    // Initials image (in-memory)
    const inits = initialsFromName(name);
    const initCanvas = document.createElement('canvas');
    initCanvas.width = 450;
    initCanvas.height = 180;
    const ictx = initCanvas.getContext('2d');
    clearCanvas(ictx, initCanvas);

    ictx.fillStyle = '#111';
    ictx.textBaseline = 'middle';
    ictx.font = "72px 'Segoe Script','Brush Script MT',cursive";
    ictx.fillText(inits || ' ', 40, initCanvas.height / 2);

    // Only set outputs in typed mode
    if (isTypedMode()) {
      sigOut.value = typedCanvas.toDataURL('image/png');
      initOut.value = initCanvas.toDataURL('image/png');
    }
  }

  typedNameEl.addEventListener('input', () => {
    // Always keep preview updated; outputs only set if typed mode
    renderTyped();
  });

  // ----------------------------
  // Draw signature pads
  // ----------------------------
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
      if (!drawing) return;
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

  function updateDrawnSignatureOutput() {
    if (isDrawnMode()) {
      sigOut.value = drawCanvas.toDataURL('image/png');
    }
  }

  function updateDrawnInitialsOutput() {
    if (!initialsCanvas || !initialsCtx) return;
    if (!initialsWrap) return;

    const shown = (initialsWrap.style.display !== 'none');
    if (isDrawnMode() && shown) {
      initOut.value = initialsCanvas.toDataURL('image/png');
    }
  }

  function initDrawPads() {
    clearCanvas(drawCtx, drawCanvas);
    bindDrawing(drawCanvas, drawCtx, updateDrawnSignatureOutput);

    if (initialsCanvas && initialsCtx) {
      clearCanvas(initialsCtx, initialsCanvas);
      bindDrawing(initialsCanvas, initialsCtx, updateDrawnInitialsOutput);
    }
  }

  if (clearDrawBtn) {
    clearDrawBtn.addEventListener('click', () => {
      clearCanvas(drawCtx, drawCanvas);
      if (isDrawnMode()) sigOut.value = '';
    });
  }

  if (useDrawAsInitialsBtn && initialsWrap) {
    useDrawAsInitialsBtn.addEventListener('click', () => {
      initialsWrap.style.display = 'block';
      // Initialize output if user already drew something earlier
      updateDrawnInitialsOutput();
    });
  }

  if (clearInitialsBtn && initialsCanvas && initialsCtx) {
    clearInitialsBtn.addEventListener('click', () => {
      clearCanvas(initialsCtx, initialsCanvas);
      if (isDrawnMode()) initOut.value = '';
    });
  }

  // ----------------------------
  // Tabs
  // ----------------------------
  qsa('.tab').forEach(btn => {
    btn.addEventListener('click', () => {
      qsa('.tab').forEach(b => b.classList.remove('active'));
      qsa('.tab-panel').forEach(p => p.classList.remove('active'));

      btn.classList.add('active');
      const tab = btn.getAttribute('data-tab');
      const panel = qs('#tab-' + tab);
      if (panel) panel.classList.add('active');

      // Normalize to backend-friendly values: typed | drawn
      methodEl.value = (tab === 'draw') ? 'drawn' : 'typed';

      // Keep previews fresh; outputs update only for active mode
      renderTyped();
      if (isDrawnMode()) {
        // If user already has ink, capture it
        updateDrawnSignatureOutput();
        updateDrawnInitialsOutput();
      }
    });
  });

  // ----------------------------
  // Style buttons
  // ----------------------------
  qsa('.sig-style').forEach(btn => {
    btn.addEventListener('click', () => {
      qsa('.sig-style').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');

      typedStyleEl.value = btn.getAttribute('data-style') || 'style1';
      renderTyped();
    });
  });

  // ----------------------------
  // Submit guardrails
  // ----------------------------
  form.addEventListener('submit', (e) => {
    normalizeMethod();

    if (isTypedMode()) {
      renderTyped();
      if (!sigOut.value || sigOut.value.indexOf('data:image') !== 0) {
        e.preventDefault();
        alert('Please type your name to generate a signature.');
        return;
      }
      // Typed initials always provided (fine)
    } else {
      // Drawn mode
      if (!sigOut.value || sigOut.value.indexOf('data:image') !== 0) {
        // Force capture at submit time
        sigOut.value = drawCanvas.toDataURL('image/png');
      }

      // If initials box is visible, capture initials; otherwise clear it
      if (initialsCanvas && initialsWrap && initialsWrap.style.display !== 'none') {
        if (!initOut.value || initOut.value.indexOf('data:image') !== 0) {
          initOut.value = initialsCanvas.toDataURL('image/png');
        }
      } else {
        initOut.value = '';
      }

      // Do NOT overwrite typedNameEl; keep user-provided legal name if present.
      // If it's empty, block submission (your HTML requires it anyway).
      if (!typedNameEl.value.trim()) {
        e.preventDefault();
        alert('Please enter your legal name before saving your signature.');
        return;
      }

      // If the drawn signature is still blank (all transparent), sigOut will still be a valid data URL.
      // We keep simple validation: user must draw something; check pixel data quickly.
      try {
        const imgData = drawCtx.getImageData(0, 0, drawCanvas.width, drawCanvas.height).data;
        let hasInk = false;
        // Scan sparsely for speed
        for (let i = 3; i < imgData.length; i += 4000) {
          if (imgData[i] !== 0) { hasInk = true; break; } // alpha channel
        }
        if (!hasInk) {
          e.preventDefault();
          alert('Please draw your signature before saving.');
          return;
        }
      } catch (err) {
        // If browser blocks getImageData (rare), fall back to allowing submit.
      }
    }
  });

  // ----------------------------
  // Init
  // ----------------------------
  initDrawPads();
  renderTyped();
  normalizeMethod();
})();
