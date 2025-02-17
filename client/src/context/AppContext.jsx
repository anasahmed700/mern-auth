import axios from "axios";
import { createContext, useEffect, useState } from "react";
import { toast } from "react-toastify";

const AppContext = createContext();
export const AppContextProvider = (props) => {
    const backendUrl = import.meta.env.VITE_BACKEND_URL;
    const [isLoggedIn, setIsLoggedIn] = useState(false);
    const [userData, setUserData] = useState(false);

    const getAuthStatus = async () => {
        try {
            const { data } = await axios.get(backendUrl + '/api/auth/is-auth', {
                withCredentials: true,
            });
            if (data.success) {
                setIsLoggedIn(true);
                getUserData();
            }
        } catch (error) {
            toast.error(error.message);
        }
    }

    const getUserData = async () => {
        try {
            const { data } = await axios.get(backendUrl + '/api/user/data', {
                withCredentials: true,
            });
            data.success ? setUserData(data.data) : toast.error(data.message);
        } catch (error) {
            toast.error(error.message);
        }
    }

    // Load user data from localStorage on initial render
    useEffect(() => {
        getAuthStatus();
    }, []);

    const value = {
        backendUrl,
        isLoggedIn, setIsLoggedIn,
        userData, setUserData,
        getUserData
    }

    return (
        <AppContext.Provider value={value}>{props.children}</AppContext.Provider>
    )
}

export default AppContext;