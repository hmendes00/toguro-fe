export interface AppState {
  appLoaded: boolean;
  customApps: Record<string, CustomApp>;
}

export type CustomApp = {
  appName: string;
  appId: string;
  appUrl: string;
  developerEmail: string;
  appVersion: string;
  target: string;
  appType: string;
  label: string;
  hasSupport: boolean;
  requiredGlobally: boolean;
};

const state: AppState = {
  appLoaded: false,
  customApps: {}
};

export default state;
