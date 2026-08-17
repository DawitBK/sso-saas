import { z } from 'zod';

export const EmailParamSchema = z.object({
  email: z.string().trim().min(1, 'email is required').email('email must be a valid email address'),
});

export const SetRolesBodySchema = z.object({
  roles: z.array(z.string().trim().min(1, 'role names must be non-empty strings')),
  grantedBy: z.string().trim().min(1).optional(),
});
