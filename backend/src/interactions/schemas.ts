import { z } from 'zod';

export const LoginBodySchema = z.object({
  email: z.string().trim().min(1, 'Email is required').email('Enter a valid email address'),
  password: z.string().min(1, 'Password is required'),
});

export const TotpBodySchema = z.object({
  code: z.string().trim().min(1, 'Enter the code from your authenticator app'),
});

export const PasswordChangeBodySchema = z.object({
  password: z.string().min(1, 'Password is required'),
  confirm: z.string().min(1, 'Please confirm your password'),
});
