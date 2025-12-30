(() => {
  // Block context menu and common inspect shortcuts
  const blockKeys = (e) => {
    const key = e.key?.toLowerCase();
    const ctrl = e.ctrlKey || e.metaKey;
    if (
      e.key === 'F12' ||
      (ctrl && e.shiftKey && ['i', 'j', 'c'].includes(key)) ||
      (ctrl && key === 'u')
    ) {
      e.preventDefault();
      e.stopPropagation();
      return false;
    }
    return undefined;
  };

  window.addEventListener('contextmenu', (e) => {
    e.preventDefault();
  });
  window.addEventListener('keydown', blockKeys, true);

  // Simple devtools presence heuristic
  const detectDevTools = () => {
    const threshold = 180;
    if (
      (window.outerWidth - window.innerWidth > threshold) ||
      (window.outerHeight - window.innerHeight > threshold)
    ) {
      console.warn('DevTools detected - interactions limited.');
    }
  };
  setInterval(detectDevTools, 2000);
})();
