import React, { useContext, useEffect, useState } from 'react';
import { AuthContext } from '../Context/AuthContext';
import { format } from 'date-fns';
import { toast } from 'react-toastify';

import '../App.css'
const Dashboard = () => {
  const { user, signOut } = useContext(AuthContext);
  const [greeting, setGreeting] = useState('');

  useEffect(() => {
    const hour = new Date().getHours();
    let newGreeting = '';

    if (hour < 12) {
      newGreeting = 'Good morning';
    } else if (hour < 18) {
      newGreeting = 'Good afternoon';
    } else {
      newGreeting = 'Good evening';
    }

    setGreeting(newGreeting);
  }, []);

  const handleEditProfile = () => {
    toast.info('Profile settings would open here');
  };

  return (
    <div className="dashboard-container">
      <div className="dashboard-header">
        <h1>{greeting}, {user?.username || 'User'}!</h1>
        <p>Welcome to your dashboard</p>
      </div>

      <div className="dashboard-content">
        <div className="dashboard-card">
          <h3>Account Information</h3>
          <div className="card-content">
            <p><strong>Username:</strong> {user?.username || 'N/A'}</p>
            <p><strong>Roles:</strong> {user?.roles?.join(', ') || 'User'}</p>
          </div>
        </div>

        <div className="dashboard-card">
          <h3>Activity</h3>
          <div className="card-content">
            <p>You successfully logged in to your account.</p>
            <p><strong>Last login:</strong> {format(new Date(), 'PPpp')}</p>
          </div>
        </div>

        <div className="dashboard-card">
          <h3>Quick Actions</h3>
          <div className="card-content">
            <button className="action-button" onClick={handleEditProfile}>
              Edit Profile
            </button>
            <button className="action-button logout" onClick={signOut}>
              Logout
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;