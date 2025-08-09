'use client';
import { useEffect, useState } from 'react';
import axios from 'axios';

export default function HistoryPage() {
  const [history, setHistory] = useState([]);

  useEffect(() => {
    axios.get('http://localhost:4000/history').then(res => setHistory(res.data));
  }, []);

  return (
    <main className="p-8">
      <h1 className="text-xl font-bold">Scan History</h1>
      <ul className="mt-4 space-y-2">
        {history.map((item) => (
          <li key={item.id} className="border p-2 rounded">
            <p><strong>{item.filename}</strong></p>
            <p>Risk: {item.riskLevel}</p>
            <p>Date: {new Date(item.uploadedAt).toLocaleString()}</p>
          </li>
        ))}
      </ul>
    </main>
  );
}