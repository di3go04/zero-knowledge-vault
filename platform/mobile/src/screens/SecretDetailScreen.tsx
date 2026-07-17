import React, { useEffect, useState } from "react";
import { View, Text, StyleSheet, ActivityIndicator, ScrollView } from "react-native";
import { useRoute } from "@react-navigation/native";
import type { RouteProp } from "@react-navigation/native";
import type { RootStackParamList } from "../navigation/RootNavigator";
import { api } from "../services/api-client";

type DetailRoute = RouteProp<RootStackParamList, "SecretDetail">;

export function SecretDetailScreen() {
  const route = useRoute<DetailRoute>();
  const { secretId } = route.params;
  const [data, setData] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.getSecret(secretId)
      .then(setData)
      .catch(console.error)
      .finally(() => setLoading(false));
  }, [secretId]);

  if (loading) {
    return (
      <View style={styles.container}>
        <ActivityIndicator color="#4ade80" />
      </View>
    );
  }

  return (
    <ScrollView style={styles.container}>
      <Text style={styles.label}>Datos cifrados (blob)</Text>
      <Text style={styles.value} selectable>
        {data?.encryptedData ?? "N/A"}
      </Text>
      <Text style={styles.label}>IV</Text>
      <Text style={styles.value} selectable>
        {data?.dataIv ?? "N/A"}
      </Text>
      <Text style={styles.note}>
        El descifrado se realiza localmente con la clave privada del usuario.
      </Text>
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: "#0f172a", padding: 16 },
  label: { color: "#94a3b8", fontSize: 12, marginTop: 16, marginBottom: 4 },
  value: {
    color: "#e2e8f0",
    fontSize: 14,
    fontFamily: "monospace",
    backgroundColor: "#1e293b",
    padding: 12,
    borderRadius: 6,
  },
  note: {
    color: "#64748b",
    fontSize: 12,
    marginTop: 24,
    textAlign: "center",
    fontStyle: "italic",
  },
});
