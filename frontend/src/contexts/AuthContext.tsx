import React, { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import toast from 'react-hot-toast';
import config from '../config.js';

interface User {
  username: string;
  token: string;
}

interface AuthContextType {
  user: User | null;
  login: (username: string, token: string) => void;
  logout: () => void;
  isAuthenticated: boolean;
  isLoading: boolean;
}

const AuthContext = createContext<AuthContextType | undefined>(undefined);

export const useAuth = (): AuthContextType => {
  const context = useContext(AuthContext);
  if (context === undefined) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

interface AuthProviderProps {
  children: ReactNode;
}

export const AuthProvider: React.FC<AuthProviderProps> = ({ children }) => {
  const [user, setUser] = useState<User | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    // Check for existing token on app startup
    const initializeAuth = async () => {
      const token = localStorage.getItem('token');
      const username = localStorage.getItem('username');

      if (token && username) {
        // Verify token with backend
        try {
          const response = await fetch(`${config.API_BASE_URL}/api/verify-token`, {
            method: 'POST',
            headers: {
              'Authorization': `Bearer ${token}`,
              'Content-Type': 'application/json',
            },
          });

          if (response.ok) {
            setUser({ username, token });
          } else {
            // Token is invalid, clear localStorage
            localStorage.removeItem('token');
            localStorage.removeItem('username');
          }
        } catch (error) {
          // Network error, but keep token for offline use
          console.warn('Could not verify token:', error);
          setUser({ username, token });
        }
      }
      setIsLoading(false);
    };

    initializeAuth();
  }, []);

  const login = (username: string, token: string) => {
    localStorage.setItem('token', token);
    localStorage.setItem('username', username);
    setUser({ username, token });
  };

  const logout = async () => {
    try {
      // Notify backend of logout
      const token = localStorage.getItem('token');
      if (token) {
        await fetch(`${config.API_BASE_URL}/api/logout`, {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${token}`,
            'Content-Type': 'application/json',
          },
        });
      }
    } catch (error) {
      console.warn('Logout request failed:', error);
    } finally {
      // Clear local state regardless of backend response
      localStorage.removeItem('token');
      localStorage.removeItem('username');
      setUser(null);
      toast.success('Logged out successfully');
    }
  };

  const value: AuthContextType = {
    user,
    login,
    logout,
    isAuthenticated: !!user,
    isLoading,
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
}; 