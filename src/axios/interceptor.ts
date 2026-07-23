import { AxiosInstance, InternalAxiosRequestConfig } from 'axios';
import { AuthClient } from '../core/AuthClient';

/**
 * Attaches a Request Interceptor to the provided Axios instance to inject the Bearer token,
 * and a Response Interceptor to automatically handle 401s by refreshing the token.
 */
export function setupAxiosInterceptors(axiosInstance: AxiosInstance, authClient: AuthClient): void {
  // Request Interceptor: Attach Token
  axiosInstance.interceptors.request.use(
    (config: InternalAxiosRequestConfig) => {
      const token = authClient.getAccessToken();
      if (token && config.headers) {
        config.headers.Authorization = `Bearer ${token}`;
      }
      return config;
    },
    (error) => Promise.reject(error)
  );

  // Response Interceptor: Handle 401 and Refresh Token
  axiosInstance.interceptors.response.use(
    (response) => response,
    async (error) => {
      const originalRequest = error.config;
      
      // If error is 401 and we haven't already retried this request
      if (error.response?.status === 401 && originalRequest && !originalRequest._retry) {
        originalRequest._retry = true;
        
        try {
          // Attempt to refresh token
          const tokenInfo = await authClient.refreshAccessToken();
          
          // Update the failed request with the new token
          if (originalRequest.headers) {
            originalRequest.headers.Authorization = `Bearer ${tokenInfo.accessToken}`;
          }
          
          // Retry the original request
          return axiosInstance(originalRequest);
        } catch (refreshError) {
          // Refresh failed, user must log in again
          authClient.logout();
          // We can't automatically redirect in a pure utility, 
          // the app should observe authState.isAuthenticated === false
          return Promise.reject(refreshError);
        }
      }
      
      return Promise.reject(error);
    }
  );
}
