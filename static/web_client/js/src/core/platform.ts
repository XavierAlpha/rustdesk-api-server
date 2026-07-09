export function detectOs(): string {
  const ua = navigator.userAgent;
  if (/android/i.test(ua)) {
    return 'Android';
  }
  if (/iphone|ipad|ipod/i.test(ua)) {
    return 'iOS';
  }
  if (/windows/i.test(ua)) {
    return 'Windows';
  }
  if (/macintosh|mac os/i.test(ua)) {
    return 'Mac OS';
  }
  if (/linux/i.test(ua)) {
    return 'Linux';
  }
  return '';
}

export function isMobileDevice(): boolean {
  if (navigator.maxTouchPoints && navigator.maxTouchPoints > 1) {
    return true;
  }
  return /android|iphone|ipad|ipod|iemobile|opera mini/i.test(
    navigator.userAgent
  );
}

export function screenInfo(): string {
  const width = window.innerWidth;
  const height = window.innerHeight;
  const dpr = window.devicePixelRatio || 1;
  return JSON.stringify({
    // Keep the same shape expected by desktop toolbar code.
    frame: {
      l: 0,
      t: 0,
      r: width,
      b: height
    },
    visibleFrame: {
      l: 0,
      t: 0,
      r: width,
      b: height
    },
    scaleFactor: dpr,
    width,
    height,
    dpr
  });
}
