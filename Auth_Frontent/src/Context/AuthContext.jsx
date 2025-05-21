import { createContext, useState, useEffect } from "react";
import { login, refreshToken } from "../services/api";

export const AuthContext = createContext();

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const token = localStorage.getItem("accessToken");
    if (token) {
      // Tokeni yoxlamaq və ya user məlumatlarını bərpa etmək
      setUser({ token });
    }
    setLoading(false);
  }, []);

  const signIn = async (credentials) => {
    try {
      console.log("AuthContext signIn - başlanğıc", credentials);
      
      // Əmin olun ki, credentials formatı düzgündür
      const loginData = {
        username: credentials.username,
        password: credentials.password
      };
      
      console.log("Hazırlanmış login data:", loginData);
      
      const response = await login(loginData);
      console.log("Login cavabı:", response.data);
      
      // Əmin olaq ki, response.data-da lazımi sahələr var
      const { accessToken, refreshToken: newRefreshToken } = response.data;
      
      if (!accessToken) {
        throw new Error("Server cavabında access token yoxdur");
      }
      
      localStorage.setItem("accessToken", accessToken);
      
      if (newRefreshToken) {
        localStorage.setItem("refreshToken", newRefreshToken);
      }
      
      setUser({ token: accessToken });
      return response.data;
    } catch (error) {
      console.error("SignIn error:", error.response || error);
      throw new Error(error.response?.data?.message || "Login failed");
    }
  };

  const signOut = () => {
    localStorage.removeItem("accessToken");
    localStorage.removeItem("refreshToken");
    setUser(null);
  };

  const refreshAccessToken = async () => {
    try {
      const refresh = localStorage.getItem("refreshToken");
      if (!refresh) {
        throw new Error("Refresh token tapılmadı");
      }
      
      const response = await refreshToken(refresh);
      const { accessToken } = response.data;
      
      if (!accessToken) {
        throw new Error("Server cavabında access token yoxdur");
      }
      
      localStorage.setItem("accessToken", accessToken);
      setUser({ token: accessToken });
      return accessToken;
    } catch (error) {
      console.error("Token yeniləmə xətası:", error);
      signOut();
      throw new Error("Token refresh failed");
    }
  };

  return (
    <AuthContext.Provider
      value={{ user, signIn, signOut, refreshAccessToken, loading }}
    >
      {children}
    </AuthContext.Provider>
  );
};