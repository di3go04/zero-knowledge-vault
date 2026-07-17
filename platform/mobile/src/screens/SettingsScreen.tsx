import React from "react";
import { View, Text, TouchableOpacity, StyleSheet } from "react-native";
import { useAuth } from "../services/AuthContext";

export function SettingsScreen() {
  const { logout } = useAuth();

  return (
    <View style={styles.container}>
      <TouchableOpacity style={styles.logoutButton} onPress={logout}>
        <Text style={styles.logoutText}>Cerrar sesión</Text>
      </TouchableOpacity>
    </View>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: "#0f172a", padding: 16 },
  logoutButton: {
    backgroundColor: "#7f1d1d",
    padding: 14,
    borderRadius: 8,
    alignItems: "center",
  },
  logoutText: { color: "#fca5a5", fontWeight: "600", fontSize: 16 },
});
