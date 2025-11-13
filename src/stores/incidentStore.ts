import {create} from 'zustand';

export interface SosIncident {
  id: string;
  message: string;
  timestamp: number;
  smsSent: boolean;
  callPlaced: boolean;
  callNumber?: string;
  recipients: string[];
}

interface IncidentState {
  incidents: SosIncident[];
  addIncident: (incident: Omit<SosIncident, 'id' | 'timestamp'>) => SosIncident;
  clearIncidents: () => void;
}

export const useIncidentStore = create<IncidentState>((set) => ({
  incidents: [],
  addIncident: (incident) => {
    const entry: SosIncident = {
      id: Date.now().toString(),
      timestamp: Date.now(),
      ...incident,
    };
    set((state) => ({incidents: [entry, ...state.incidents].slice(0, 100)}));
    return entry;
  },
  clearIncidents: () => set({incidents: []}),
}));
