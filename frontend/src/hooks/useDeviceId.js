import FingerprintJS from "@fingerprintjs/fingerprintjs-pro";
import { useEffect, useState } from "react";

export default function useDeviceId() {
  const [fingerPrintInstance, setFingerPrintInstance] = useState();
  const [deviceId, setDeviceId] = useState();

  useEffect(() => {
    // const fpPromise = FingerprintJS.load({
    //   apiKey: process.env.REACT_APP_FINGERPRINT_BROWSER_TOKEN,
    //   region: "ap",
    // });
    // fpPromise.then((res) => console.log(res));
    // setFingerPrintInstance(fpPromise);
    const fpPromise = import(
      `https://fpjscdn.net/v3/${process.env.REACT_APP_FINGERPRINT_BROWSER_TOKEN}`
    ).then((FingerprintJS) =>
      FingerprintJS.load({
        region: "ap",
      })
    );
    // Get the visitorId when you need it.
    // fpPromise
    //   .then((fp) => fp.get())
    //   .then((result) => {
    //     const visitorId = result.visitorId;
    //     console.log(visitorId);
    //   });
    setFingerPrintInstance(fpPromise);
  }, []);

  useEffect(() => {
    if (fingerPrintInstance) {
      getFingerPrintInfo();
    }
  }, [fingerPrintInstance]);

  const getFingerPrintInfo = () => {
    fingerPrintInstance
      .then((fp) => fp.get())
      .then((result) => {
        setDeviceId(result.visitorId);
      });
  };
  return { deviceId };
}
