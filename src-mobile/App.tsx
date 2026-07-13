import React, { useState } from 'react';
import { View, Text, TextInput, Button, StyleSheet, SafeAreaView } from 'react-native';

export default function App() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [vault, setVault] = useState(null);

  const VAULT_URL = 'http://localhost:3000';

  async function login() {
    const res = await fetch(`${VAULT_URL}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email }),
    });
    const data = await res.json();
    // Derive masterKey + decrypt privateKey locally (requires Web Crypto polyfill)
    setVault(data);
  }

  if (vault) {
    return (
      <SafeAreaView style={styles.container}>
        <Text style={styles.title}>ZK Vault</Text>
        <Text style={styles.subtitle}>Welcome {vault.email}</Text>
        <Button title="Logout" onPress={() => setVault(null)} />
      </SafeAreaView>
    );
  }

  return (
    <SafeAreaView style={styles.container}>
      <Text style={styles.title}>ZK Vault</Text>
      <TextInput style={styles.input} placeholder="Email" value={email} onChangeText={setEmail} autoCapitalize="none" />
      <TextInput style={styles.input} placeholder="Master Password" value={password} onChangeText={setPassword} secureTextEntry />
      <Button title="Unlock" onPress={login} />
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, padding: 20, backgroundColor: '#0a0e1a' },
  title: { fontSize: 24, fontWeight: 'bold', color: '#10b981', marginBottom: 20, textAlign: 'center' },
  subtitle: { fontSize: 16, color: '#ccc', marginBottom: 10 },
  input: { backgroundColor: '#1a1e2a', color: '#fff', padding: 12, borderRadius: 8, marginBottom: 12 },
});
