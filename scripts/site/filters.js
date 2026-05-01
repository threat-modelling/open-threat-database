(function () {
  const grid = document.getElementById('threat-grid');
  const empty = document.getElementById('empty-state');
  const filtersEl = document.getElementById('filters');
  if (!grid || !filtersEl) return;

  const cards = Array.from(grid.querySelectorAll('.threat-card'));

  function selectedValues(filter) {
    return Array.from(
      filtersEl.querySelectorAll('input[data-filter="' + filter + '"]:checked')
    ).map((el) => el.value);
  }

  function apply() {
    const stride = selectedValues('stride');
    const severity = selectedValues('severity');
    let visible = 0;
    for (const card of cards) {
      const cardStride = (card.dataset.stride || '').split(' ').filter(Boolean);
      const cardSev = card.dataset.severity || '';
      const strideOk = stride.length === 0 || stride.some((s) => cardStride.includes(s));
      const sevOk = severity.length === 0 || severity.includes(cardSev);
      const show = strideOk && sevOk;
      card.hidden = !show;
      if (show) visible++;
    }
    if (empty) empty.hidden = visible !== 0;
  }

  filtersEl.addEventListener('change', (e) => {
    if (e.target && e.target.matches('input[type="checkbox"]')) apply();
  });

  const reset = document.getElementById('reset-filters');
  if (reset) {
    reset.addEventListener('click', () => {
      filtersEl
        .querySelectorAll('input[type="checkbox"]:checked')
        .forEach((el) => {
          el.checked = false;
        });
      apply();
    });
  }

  apply();
})();
