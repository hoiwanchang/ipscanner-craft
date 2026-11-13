import html2canvas from 'html2canvas';
import { saveScreenshot, screenshotTarget } from './api';

function frames(count: number, budgetMs: number) {
  return new Promise<void>((resolve) => {
    let seen = 0;
    const done = () => resolve();
    const timer = window.setTimeout(done, budgetMs);
    const tick = () => {
      seen += 1;
      if (seen >= count) {
        window.clearTimeout(timer);
        done();
      } else {
        requestAnimationFrame(tick);
      }
    };
    requestAnimationFrame(tick);
  });
}

async function shoot(root: HTMLElement) {
  const canvas = await html2canvas(root, {
    backgroundColor: getComputedStyle(root).backgroundColor || '#ffffff',
    scale: 1,
    logging: false,
    width: root.clientWidth,
    height: root.clientHeight,
    windowWidth: root.clientWidth,
    windowHeight: root.clientHeight,
  });
  return canvas.toDataURL('image/png');
}

export async function captureWhenAsked() {
  let target: string | null = null;
  try {
    target = await screenshotTarget();
  } catch {
    return;
  }
  if (!target) return;

  await frames(120, 8000);
  const root = document.getElementById('app');
  if (!root) return;

  for (let attempt = 0; attempt < 3; attempt += 1) {
    try {
      const data = await shoot(root);
      if (data.length > 2000) {
        await saveScreenshot(data);
        return;
      }
    } catch (error) {
      console.error('screenshot attempt failed', error);
    }
    await frames(30, 1500);
  }
  console.error('could not produce a screenshot');
}