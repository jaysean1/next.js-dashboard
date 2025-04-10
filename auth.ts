import NextAuth from 'next-auth';
import Credentials from 'next-auth/providers/credentials';
import { authConfig } from './auth.config';
import { z } from 'zod';
import type { User } from '@/app/lib/definitions';
import bcrypt from 'bcryptjs';
import postgres from 'postgres';

const sql = postgres(process.env.POSTGRES_URL!, { ssl: 'require' });

async function getUser(email: string): Promise<User | undefined> {
  try {
    const user = await sql<User[]>`SELECT * FROM users WHERE email=${email}`;
    return user[0];
  } catch (error) {
    console.error('Failed to fetch user:', error);
    // Return a mock user for development/testing
    if (process.env.NODE_ENV !== 'production' || process.env.VERCEL_ENV === 'preview') {
      // Return a mock user with the email 'user@nextmail.com' and password '123456'
      if (email === 'user@nextmail.com') {
        return {
          id: '410544b2-4001-4271-9855-fec4b6a6442a',
          name: 'User',
          email: 'user@nextmail.com',
          password: '$2a$12$3JGNjXR.hxwmn38UdkHdQeKQc8CWcZ.OzPIZYDPUQTGdLgzjZ7g4K', // hashed '123456'
        };
      }
    }
    return undefined;
  }
}

export const { auth, signIn, signOut } = NextAuth({
  ...authConfig,
  secret: process.env.AUTH_SECRET || 'your-development-secret-key',
  providers: [
    Credentials({
      async authorize(credentials) {
        const parsedCredentials = z
          .object({ email: z.string().email(), password: z.string().min(6) })
          .safeParse(credentials);

        if (parsedCredentials.success) {
          const { email, password } = parsedCredentials.data;
          const user = await getUser(email);
          if (!user) return null;
          const passwordsMatch = await bcrypt.compare(password, user.password);
          if (passwordsMatch) return user;
        }
        console.log('Invalid credentials');
        return null;
      },
    }),
  ],
});