import { render, screen } from '@testing-library/react';
import App from './App';

test('renders app title and default tab', () => {
  render(<App />);
  expect(screen.getByRole('heading', { name: /ứng dụng mã hóa/i })).toBeInTheDocument();
  expect(screen.getByRole('button', { name: /mã hóa đối xứng/i })).toBeInTheDocument();
  expect(screen.getByRole('button', { name: /bất đối xứng/i })).toBeInTheDocument();
  expect(screen.getByRole('button', { name: /^mã hóa$/i })).toBeInTheDocument();
  expect(screen.getByRole('button', { name: /^giải mã$/i })).toBeInTheDocument();
});
