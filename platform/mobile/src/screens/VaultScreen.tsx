import React, { useEffect, useState } from "react";
import {
  View,
  Text,
  FlatList,
  TouchableOpacity,
  StyleSheet,
  ActivityIndicator,
} from "react-native";
import { useNavigation } from "@react-navigation/native";
import type { NativeStackNavigationProp } from "@react-navigation/native-stack";
import type { RootStackParamList } from "../navigation/RootNavigator";
import { api, Secret } from "../services/api-client";
import { useAuth } from "../services/AuthContext";

type NavProp = NativeStackNavigationProp<RootStackParamList, "Vault">;

export function VaultScreen() {
  const navigation = useNavigation<NavProp>();
  const { logout } = useAuth();
  const [secrets, setSecrets] = useState<Secret[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    api.listSecrets()
      .then((res) => setSecrets(res.data))
      .catch(console.error)
      .finally(() => setLoading(false));
  }, []);

  return (
    <View style={styles.container}>
      {loading ? (
        <ActivityIndicator color="#4ade80" style={{ marginTop: 40 }} />
      ) : (
        <FlatList
          data={secrets}
          keyExtractor={(item) => item.id}
          ListEmptyComponent={
            <Text style={styles.empty}>No hay secretos</Text>
          }
          renderItem={({ item }) => (
            <TouchableOpacity
              style={styles.item}
              onPress={() =>
                navigation.navigate("SecretDetail", { secretId: item.id })
              }
            >
              <Text style={styles.itemTitle}>{item.title}</Text>
              <Text style={styles.itemDate}>
                {new Date(item.createdAt).toLocaleDateString()}
              </Text>
            </TouchableOpacity>
          )}
        />
      )}
    </View>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: "#0f172a", padding: 16 },
  empty: { color: "#64748b", textAlign: "center", marginTop: 40, fontSize: 16 },
  item: {
    backgroundColor: "#1e293b",
    padding: 16,
    borderRadius: 8,
    marginBottom: 8,
  },
  itemTitle: { color: "#e2e8f0", fontSize: 16, fontWeight: "500" },
  itemDate: { color: "#64748b", fontSize: 12, marginTop: 4 },
});
