"use client";

import { useSession } from "./session-store";

const HOME_REGION_KEY = "zk-vault-home-region";
const TRAVEL_MODE_KEY = "zk-vault-travel-mode";

export interface GeoLocation {
  latitude: number;
  longitude: number;
  country?: string;
  region?: string;
}

/**
 * Obtiene la ubicación aproximada del usuario usando Geolocation API.
 * Solo se usa al inicio de sesión para establecer la "home region".
 */
export async function getCurrentLocation(): Promise<GeoLocation | null> {
  try {
    const pos = await new Promise<GeolocationPosition>((resolve, reject) => {
      navigator.geolocation.getCurrentPosition(resolve, reject, {
        enableHighAccuracy: false,
        timeout: 5000,
        maximumAge: 5 * 60 * 1000,
      });
    });
    return {
      latitude: pos.coords.latitude,
      longitude: pos.coords.longitude,
    };
  } catch {
    return null;
  }
}

/**
 * Almacena la ubicación actual como "home region" después de un login exitoso.
 */
export function setHomeRegion(): void {
  if (typeof window === "undefined") return;
  getCurrentLocation().then((loc) => {
    if (loc) {
      try {
        localStorage.setItem(HOME_REGION_KEY, JSON.stringify(loc));
        localStorage.removeItem(TRAVEL_MODE_KEY);
      } catch { /* no-op */ }
    }
  });
}

/**
 * Obtiene la home region almacenada.
 */
export function getHomeRegion(): GeoLocation | null {
  if (typeof window === "undefined") return null;
  try {
    const stored = localStorage.getItem(HOME_REGION_KEY);
    return stored ? (JSON.parse(stored) as GeoLocation) : null;
  } catch {
    return null;
  }
}

const DISTANCE_THRESHOLD_KM = 500;

/**
 * Calcula la distancia (km) entre dos coordenadas (Haversine).
 */
function haversineKm(a: GeoLocation, b: GeoLocation): number {
  const R = 6371;
  const dLat = ((b.latitude - a.latitude) * Math.PI) / 180;
  const dLon = ((b.longitude - a.longitude) * Math.PI) / 180;
  const lat1 = (a.latitude * Math.PI) / 180;
  const lat2 = (b.latitude * Math.PI) / 180;
  const h =
    Math.sin(dLat / 2) ** 2 +
    Math.sin(dLon / 2) ** 2 * Math.cos(lat1) * Math.cos(lat2);
  return R * 2 * Math.atan2(Math.sqrt(h), Math.sqrt(1 - h));
}

/**
 * Verifica si el usuario está en una región diferente a su home region.
 * Si es así, activa el modo travel y borra datos locales sensibles.
 */
export async function detectRegionChange(): Promise<boolean> {
  const home = getHomeRegion();
  if (!home) return false;

  const current = await getCurrentLocation();
  if (!current) return false;

  const distance = haversineKm(home, current);
  if (distance > DISTANCE_THRESHOLD_KM) {
    activateTravelMode();
    return true;
  }
  return false;
}

/**
 * Activa el modo travel: borra CrypoKey refs y datos locales sensibles.
 */
export function activateTravelMode(): void {
  try {
    localStorage.setItem(TRAVEL_MODE_KEY, "true");
    localStorage.removeItem(HOME_REGION_KEY);
  } catch { /* no-op */ }

  const state = useSession.getState();
  state.logout();

  try {
    sessionStorage.clear();
  } catch { /* no-op */ }
}

/**
 * Verifica si el modo travel está activo.
 */
export function isTravelModeActive(): boolean {
  if (typeof window === "undefined") return false;
  return localStorage.getItem(TRAVEL_MODE_KEY) === "true";
}

/**
 * Desactiva el modo travel cuando el usuario vuelve a su región de origen.
 */
export function deactivateTravelMode(): void {
  try {
    localStorage.removeItem(TRAVEL_MODE_KEY);
  } catch { /* no-op */ }
}