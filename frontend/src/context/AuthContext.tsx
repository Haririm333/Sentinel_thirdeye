import React, { createContext, useContext, useState, useEffect } from 'react';
import { UserPersona } from '../types';

export const AVAILABLE_PERSONAS: UserPersona[] = [
  {
    id: 'usr_req_sarah',
    name: 'Sarah Jenkins',
    role: 'Procurement Specialist',
    systemRole: 'REQUESTER',
    description: 'Finance Operations - Submits vendor payment & account changes',
    avatarColor: 'bg-indigo-600',
  },
  {
    id: 'usr_appr_elena',
    name: 'Elena Rostova',
    role: 'Finance Controller',
    systemRole: 'FINANCE_APPROVER',
    description: 'First Human Approver - Inspects vendor legitimacy & banking proof',
    avatarColor: 'bg-emerald-600',
  },
  {
    id: 'usr_appr_david',
    name: 'David Sterling',
    role: 'VP of Financial Ops',
    systemRole: 'FINANCE_APPROVER',
    description: 'Second Human Approver - Independent executive sign-off',
    avatarColor: 'bg-amber-600',
  },
  {
    id: 'usr_admin_alex',
    name: 'Alex Vance',
    role: 'Security & System Admin',
    systemRole: 'FINANCE_ADMIN',
    description: 'System Administrator - Policy administration & emergency overrides',
    avatarColor: 'bg-purple-600',
  },
  {
    id: 'usr_audit_rachel',
    name: 'Rachel Thorne',
    role: 'Senior Cyber Auditor',
    systemRole: 'AUDITOR',
    description: 'Security Operations & Compliance - Read-only forensic oversight',
    avatarColor: 'bg-cyan-600',
  },
];

interface AuthContextType {
  activePersona: UserPersona;
  setActivePersona: (persona: UserPersona) => void;
  availablePersonas: UserPersona[];
}

const AuthContext = createContext<AuthContextType>({
  activePersona: AVAILABLE_PERSONAS[1], // Default to Elena Rostova (Approver)
  setActivePersona: () => {},
  availablePersonas: AVAILABLE_PERSONAS,
});

export const AuthProvider: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const [activePersona, setActivePersonaState] = useState<UserPersona>(() => {
    const saved = localStorage.getItem('sentinel_active_persona');
    if (saved) {
      const found = AVAILABLE_PERSONAS.find((p) => p.id === saved);
      if (found) return found;
    }
    return AVAILABLE_PERSONAS[1];
  });

  const setActivePersona = (persona: UserPersona) => {
    setActivePersonaState(persona);
    localStorage.setItem('sentinel_active_persona', persona.id);
  };

  useEffect(() => {
    localStorage.setItem('sentinel_active_persona', activePersona.id);
  }, [activePersona]);

  return (
    <AuthContext.Provider value={{ activePersona, setActivePersona, availablePersonas: AVAILABLE_PERSONAS }}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => useContext(AuthContext);
