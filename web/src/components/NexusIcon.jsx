import React from 'react';

const NexusIcon = ({ className = '', size = 32 }) => {
  return (
    <img 
      src="https://customer-assets.emergentagent.com/job_61e30ec6-d837-4de0-a6a7-710630fcfeac/artifacts/ocjqjr57_download.png"
      alt="Nexus"
      className={className}
      style={{ width: size, height: size, objectFit: 'contain' }}
    />
  );
};

export default NexusIcon;
