import "./App.css";
import useDeviceId from "./hooks/useDeviceId";
import useLocation from "./hooks/useLocation";
import useIdle from "./hooks/useIdle";
import { useEffect, useState } from "react";

function App() {
  /**
   * To fix Broken Authentication
   */
  const { deviceId } = useDeviceId();
  const { locationData } = useLocation();

  const logout = () => {
    // Logout code
    console.log("user logout");
  };
  const { isIdle } = useIdle({ onIdle: logout, idleTime: 0.25 });

  /**
   * To fix XSS
   */
  // const validationElement = document.getElementById("validation");
  // const validationMessage = `Oops! This seems like an invalid referral code.`;
  // XSS code - Buggy code
  //   validationMessage = `Oops! This seems like an invalid referral code.
  // <script>
  //   ...
  //   alert('Congrats! You've won a prize');
  //   ...
  // </script>`;
  //   validationElement.append(validationMessage);

  // Valid code
  const [validationMessage, setValidationMessage] = useState("");
  const validateMessage = async () => {
    setTimeout(() => {
      setValidationMessage(`Invalid referral code, <script></script>`);
    }, 1000);
  };

  /**
   * To fix Command Injection
   */
  // Without validated input
  // const getAppVersion = async () => {
  //   const response = await fetch("http://localhost:8080/?versionFile=v1.txt", {
  //     mode: "cors",
  //   });
  //   const data = await response.json();
  //   console.log(data);
  // };

  // With validated input
  const validateQueryParam = (queryParam) => {
    const infiltratedParams = queryParam.split("&&");
    console.log(infiltratedParams);
    if (infiltratedParams.length > 1) return false;
    else return true;
  };

  const getAppVersion = async () => {
    const queryParam = "versionFile=v1.txt&&cd%20secrets";
    const isValidQueryParam = validateQueryParam(queryParam);
    if (!isValidQueryParam) {
      alert("invalid query params");
      return;
    }
    const response = await fetch(`http://localhost:8080/?${queryParam}`, {
      mode: "cors",
    });
    const data = await response.json();
    console.log(data);
  };

  useEffect(() => {
    getAppVersion();
  }, []);

  return (
    <div className="App">
      <h1>React Vulnerability Fixes</h1>
      <br />
      {/* To fix Broken Authentication */}
      <div className="App-header">
        <h3>Device ID - {deviceId}</h3>
        <h3>
          Location Info -
          <div
            style={{
              color: "darkgray",
              display: "flex",
              flexDirection: "column",
            }}
          >
            {locationData &&
              Object.keys(locationData)?.map((locationDataKey) => (
                <span style={{ marginRight: 10 }} key={locationDataKey}>
                  {locationDataKey} - {locationData[locationDataKey]}
                </span>
              ))}
          </div>
        </h3>
      </div>
      <br />
      <div className="App-header">
        {isIdle ? "User will be logged out" : "User is not idle"}
      </div>

      <br />
      {/* To fix XSS */}
      {/* Buggy code */}
      {/* <div id="validation"></div>
      <input placeholder="Enter your referral code below" />
      <button>Submit</button> */}
      {/* Proper code */}
      <div className="App">
        <input placeholder="Enter your referral code" />
        <button onClick={validateMessage}>Submit</button>
        <div>{validationMessage}</div>
      </div>
    </div>
  );
}

export default App;
