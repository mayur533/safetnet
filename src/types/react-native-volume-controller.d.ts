declare module 'react-native-volume-controller' {
  interface VolumeEvent {
    volume: number;
  }

  type Listener = (event: VolumeEvent) => void;

  const VolumeController: {
    addListener: (listener: Listener) => {remove: () => void};
    setVolume: (volume: number, config?: {playSound?: boolean}) => void;
  };

  export default VolumeController;
}
