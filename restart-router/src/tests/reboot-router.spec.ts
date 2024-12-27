import { test, expect } from '@playwright/test';
import dotenv from 'dotenv'
import path from 'path';
dotenv.config({ path: path.resolve(__dirname, '../.env') });

test('reboot_router', async ({ page }) => {
  if (!process.env.ROUTER_WEB_USERNAME) {
    throw Error('Please define the ROUTER_WEB_USERNAME in .env');
  }
  if (!process.env.ROUTER_WEB_PASSWORD) {
    throw Error('Please define the ROUTER_WEB_PASSWORD in .env');
  }
  if (!process.env.ROUTER_WEB_URL) {
    throw Error('Please define the ROUTER_WEB_URL in .env');
  }
  await page.goto(process.env.ROUTER_WEB_URL);
  await expect(page.getByRole('heading', { name: 'Bienvenido' })).toBeVisible();
  await page.getByPlaceholder('Username').click();
  await page.getByPlaceholder('Username').fill(process.env.ROUTER_WEB_USERNAME);
  await page.getByPlaceholder('Password').click();
  await page.getByPlaceholder('Password').fill(process.env.ROUTER_WEB_PASSWORD);
  await page.getByRole('button', { name: 'Iniciar la sesión' }).click();
  await page.waitForTimeout(1000);
  await page.getByRole('link', { name: 'Estado y Soporte' }).click();
  await page.waitForTimeout(1000);
  await page.locator('#sub-navigation-item-1880').getByText('Reiniciar').click();
  await page.waitForTimeout(1000);
  await expect(page.getByRole('button', { name: 'Reiniciar' })).toBeVisible();
  await page.getByRole('button', { name: 'Reiniciar' }).click();
  await page.waitForTimeout(1000); // for the confirm popup to show.
  await page.getByRole('button', { name: 'Aplicar' }).click();
});
