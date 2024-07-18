import { useState, useEffect } from "react";

export default function useLocation() {
  const [locationData, setLocationData] = useState();

  useEffect(() => {
    getLocationData();
  }, []);

  const getLocationData = async () => {
    if (navigator.geolocation) {
      navigator.geolocation.getCurrentPosition(
        (position) => {
          console.log(position);
          setLocationData({
            latitude: position.coords.latitude,
            longitude: position.coords.longitude,
          });
        },
        (error) => {
          console.error("Error getting location:", error);
        }
      );
    } else {
      console.error("Geolocation is not supported by this browser.");
    }
  };

  return { locationData };
}
