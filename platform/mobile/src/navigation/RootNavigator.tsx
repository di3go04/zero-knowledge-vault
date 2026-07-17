import React from "react";
import { createNativeStackNavigator } from "@react-navigation/native-stack";
import { useAuth } from "../services/AuthContext";
import { LoginScreen } from "../screens/LoginScreen";
import { VaultScreen } from "../screens/VaultScreen";
import { SecretDetailScreen } from "../screens/SecretDetailScreen";
import { SettingsScreen } from "../screens/SettingsScreen";

export type RootStackParamList = {
  Login: undefined;
  Vault: undefined;
  SecretDetail: { secretId: string };
  Settings: undefined;
};

const Stack = createNativeStackNavigator<RootStackParamList>();

export function RootNavigator() {
  const { session } = useAuth();

  return (
    <Stack.Navigator
      screenOptions={{
        headerStyle: { backgroundColor: "#0f172a" },
        headerTintColor: "#e2e8f0",
        contentStyle: { backgroundColor: "#0f172a" },
      }}
    >
      {session ? (
        <>
          <Stack.Screen
            name="Vault"
            component={VaultScreen}
            options={{ title: "Zero-Knowledge Vault" }}
          />
          <Stack.Screen
            name="SecretDetail"
            component={SecretDetailScreen}
            options={{ title: "Secreto" }}
          />
          <Stack.Screen
            name="Settings"
            component={SettingsScreen}
            options={{ title: "Configuración" }}
          />
        </>
      ) : (
        <Stack.Screen
          name="Login"
          component={LoginScreen}
          options={{ headerShown: false }}
        />
      )}
    </Stack.Navigator>
  );
}
