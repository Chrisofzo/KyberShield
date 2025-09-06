import axios from "axios";

const API_BASE = "http://195.246.231.139/api";

export async function login(username, password, mfaCode) {
  return axios.post(`${API_BASE}/login`, {
    username,
    password,
    mfa_code: mfaCode
  }, { withCredentials: true });
}

export async function register(username, password) {
  return axios.post(`${API_BASE}/register`, {
    username,
    password
  });
}

export async function getProfile() {
  return axios.get(`${API_BASE}/user/profile`, { withCredentials: true });
}

export async function logout() {
  return axios.post(`${API_BASE}/logout`, {}, { withCredentials: true });
}