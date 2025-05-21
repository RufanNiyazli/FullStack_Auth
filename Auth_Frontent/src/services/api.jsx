import axios from 'axios';

// API instansı yaradılır
const api = axios.create({
  baseURL: 'http://localhost:8080', // Backend URL-inizi buraya yazın
  headers: {
    'Content-Type': 'application/json' // Content-Type tənzimlənir
  }
});

// Request interceptor: Hər sorğuya access token əlavə edir
api.interceptors.request.use((config) => {
  const token = localStorage.getItem('accessToken');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
}, (error) => {
  return Promise.reject(error);
});

// Response interceptor: 401 xətası alındıqda refresh token ilə yeniləmə
api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const originalRequest = error.config;
    if (error.response?.status === 401 && !originalRequest._retry) {
      originalRequest._retry = true;
      try {
        const refresh = localStorage.getItem('refreshToken');
        if (refresh) {
          const response = await refreshToken(refresh);
          const { accessToken, refreshToken: newRefreshToken } = response.data;
          // Yeni tokenləri saxla
          localStorage.setItem('accessToken', accessToken);
          if (newRefreshToken) localStorage.setItem('refreshToken', newRefreshToken);
          // Orijinal sorğuya yeni token əlavə et
          originalRequest.headers.Authorization = `Bearer ${accessToken}`;
          return api(originalRequest); // Orijinal sorğunu təkrar göndər
        }
      } catch (err) {
        // Refresh token uğursuz olarsa, xətanı ötür
        console.error("Token yeniləmə xətası:", err);
        return Promise.reject(err);
      }
    }
    return Promise.reject(error);
  }
);

// Əlavə debug funksiyası - sorğunun necə getdiyini izləmək üçün
const debugRequest = (url, data) => {
  console.log(`Sorğu URL: ${url}`);
  console.log(`Sorğu Data:`, data);
};

// API funksiyaları
export const register = (data) => {
  debugRequest('/register', data);
  return api.post('/register', data);
};

export const login = (data) => {
  debugRequest('/authenticate', data);
  return api.post('/authenticate', data);
};

export const refreshToken = (token) => {
  debugRequest('/refreshAccessToken', { token });
  return api.post('/refreshAccessToken', { token });
};

export default api;