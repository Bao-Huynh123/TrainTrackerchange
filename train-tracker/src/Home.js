 import './styles/Home.css';
import React, { useState, useEffect } from 'react';
import TrainList from './TrainList';
import Search from './Search';
import TrainPopup from './TrainPopup'; 



/* 
import './styles/Home.css';
import React, { useState, useEffect } from 'react';
import TrainList from './TrainList';
import Search from './Search';
import TrainPopup from './TrainPopup';
import { IoClose } from "react-icons/io5"; */




import { IoClose } from "react-icons/io5";

/**
 * Component displaying home page.
 * @component
 * @module Home
 * @param {object[]} allRoutes - The list of objects representing all available Amtrak routes.
 * @param {object[]} allStations - The list of objects representing all available Amtrak stations.
 * @param {function} setRefresh - The function allowing app-wide toggling of refresh state.
 * @param {object[]} currentTrains - The list of objects representing trains matching the current search criteria.
 * @param {object} globalSearchObject - The state object containing app-wide searching criteria.
 * @param {function} setGlobalSearchObject - The setter function for the state object containing app-wide searching criteria.
 * @returns {JSX.Element} The home page component.
 */
function Home({allRoutes, allStations, setRefresh, currentTrains, globalSearchObject, setGlobalSearchObject
}){
    const [selectedTrain, setSelectedTrain] = useState({});
    const [showModal, setShowModal] = useState(false);
    const [darkMode, setDarkMode] = useState(false);


    const getStationOptions = () => {
        let renderedStations = allStations.map(station => {
            return <option value={station.stationCode} key={station.stationCode}>{station.stationCode} - {station.name}</option>
        })
        renderedStations.unshift(<option value={""} key={""}>{}</option>);
        return renderedStations;
    }

    

     useEffect(() => { //!NEW, BUTTON TOGGGLE FOR DARK MODE
    if (darkMode) {
        document.body.classList.add("dark-theme");
    } else {
        document.body.classList.remove("dark-theme");
    }
}, [darkMode]);  


    const getRouteOptions = () => {
        let renderedRoutes = allRoutes.sort((a, b) => (a.Name).localeCompare(b.Name)).map(route => {
            return <option value={route.Name} key={route.Name}>{route.Name}</option>
        });
        renderedRoutes.unshift(<option value={""} key={""}></option>);
        return renderedRoutes;
    }

    function handleTrainClick(train){
        setShowModal(true);
        setSelectedTrain(train);
    }

    const handleModalClose = () => {
        setShowModal(false);
    };

    const closeButton = (<div>
        <div onClick={handleModalClose} className='close-button'><IoClose size={'3rem'}/></div>
    </div>);

    const modal = <TrainPopup onClose={handleModalClose} actionBar={closeButton} train={selectedTrain}/>
    return (
        <div className='home-page'>
            
            <div className='search-container'>
              <Search className='Search'
                routes = {getRouteOptions()}
                stations = {getStationOptions()}
                setRefreshState={setRefresh}
                globalSearchObject={globalSearchObject}
                setGlobalSearchObject={setGlobalSearchObject}
              />
              </div>
              <div className='app-train-list-container'>
                <TrainList className = 'TrainList' 
                    trains={currentTrains}
                    handleTrainClick={handleTrainClick}
                />
              </div>
              <div>
                {showModal && modal}
              </div>
        </div>
    )
}
export default Home;